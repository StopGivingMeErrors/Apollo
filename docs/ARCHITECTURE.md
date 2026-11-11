# Sentinel SOC — How It Works

This document explains what every part of the system does and how a packet
arriving at a honeypot becomes an alert, a case, and a firewall rule.

For deployment, see [`DEPLOYMENT.md`](./DEPLOYMENT.md). For a feature summary,
see the root [`README.md`](../README.md).

---

## 1. The shape of the system

Sentinel is a single FastAPI process that does four jobs at once, plus a static
React dashboard that observes it.

```
┌─────────────────────────── backend (one process) ───────────────────────────┐
│                                                                             │
│  SENSORS                  PIPELINE                      STATE               │
│  ┌──────────────┐         ┌────────────────────┐        ┌────────────────┐  │
│  │ SSH    :2222 │         │ 1. enrich (geo+    │        │                │  │
│  │ HTTP   :8080 │────────▶│    intel tags)     │───────▶│  SQLite        │  │
│  │ FTP    :2121 │  events │ 2. escalate on     │        │  8 tables      │  │
│  │ Telnet :2323 │         │    repeat offence  │        │                │  │
│  └──────────────┘         │ 3. MITRE + risk    │        └────────────────┘  │
│  ┌──────────────┐         │ 4. fingerprint →   │                 │          │
│  │ simulator    │────────▶│    dedupe alert    │                 │          │
│  │ (ambient)    │         │ 5. correlate       │                 ▼          │
│  └──────────────┘         │    campaign        │        ┌────────────────┐  │
│                           │ 6. auto-contain    │        │  REST API      │  │
│                           └─────────┬──────────┘        │  /api/*        │  │
│                                     │                   └────────────────┘  │
│                                     ▼                            │          │
│                           ┌────────────────────┐                 │          │
│                           │ publish() → SSE    │                 │          │
│                           └─────────┬──────────┘                 │          │
└─────────────────────────────────────┼────────────────────────────┼──────────┘
                                      │ text/event-stream          │ fetch
                                      ▼                            ▼
                           ┌──────────────────────────────────────────┐
                           │  React SPA — 6 views, one shared context │
                           └──────────────────────────────────────────┘
```

Everything downstream of the sensors is genuine: the detection rules, the
deduplication, the correlation, the state machines, the SLA clocks and the
metrics all operate on stored data. The *inputs* are partly synthetic, and the
system labels which is which — see §11.

---

## 2. The sensors

`honeypots.py` starts four `asyncio` TCP servers. Each accepts a connection,
optionally writes a service banner to look like real software, reads up to 2 KB
with a timeout, closes the socket, and hands the payload to the pipeline.

| Port | Emulates | Banner sent | Read timeout |
|---|---|---|---|
| 2222 | OpenSSH | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | 6s |
| 8080 | Apache | none (replies `HTTP/1.1 200` + `Server: Apache/2.4.57` after logging) | 5s |
| 2121 | ProFTPD | `220 ProFTPD 1.3.7 Server (ProFTPD) ready` (replies `530 Login incorrect`) | 6s |
| 2323 | Debian telnet | `Debian GNU/Linux 11 / localhost login:` | 8s |

The banners matter. Automated scanners fingerprint the service before choosing
an exploit, so responding with a plausible version string produces far more
interesting follow-up traffic than an immediate disconnect.

**Source IP resolution.** When the peer address is loopback, `resolve_source_ip`
scans the payload for `X-Forwarded-For:` or `src=` and uses that instead:

```21:28:backend/honeypots.py
def resolve_source_ip(peer: str, payload: str) -> str:
    """Prefer spoofed/demo source when traffic is generated locally."""
    if peer not in ("127.0.0.1", "::1", "localhost"):
        return peer
```

This exists so locally generated test traffic still geolocates onto the map.
It only ever applies to loopback connections, so a real remote attacker cannot
use it to spoof their origin.

---

## 3. Classification — payload to threat type

Each honeypot classifies its own traffic before handing it on. The rules are
literal substring matches, evaluated in order.

**HTTP (port 8080)** — first match wins:

| Test | Threat | Severity |
|---|---|---|
| payload contains `select`, `union`, `drop`, `insert`, `delete`, `' --`, `1=1`, or `or 1` | SQL Injection | critical |
| path contains `/wp-login`, `/phpmyadmin`, `/.env`, `/admin`, `/shell`, `/config`, `/.git` | Web Scanner | high |
| contains `/../` or `%2e%2e` | Path Traversal | high |
| anything else | HTTP Probe | low |

**SSH (port 2222)** — length is the signal, since a bare port scan disconnects
without sending anything while a credential stuffer sends a key exchange:

| Test | Threat | Severity |
|---|---|---|
| payload longer than 50 bytes | SSH Brute Force | critical |
| any payload | SSH Brute Force | high |
| empty payload | SSH Probe | medium |

**FTP (port 2121)** — `FTP Anonymous Access` if the payload contains
`anonymous`, otherwise `FTP Auth Attempt`. Always medium.

**Telnet (port 2323)** — always `Telnet Login Attempt`, high.

### MITRE ATT&CK mapping

`detection.py` maps each threat type to a technique. Unknown types fall back to
`T1595` (Active Scanning).

| Threat type | Technique | Tactic |
|---|---|---|
| SSH Brute Force | T1110.001 | Credential Access |
| Telnet Login Attempt | T1110.001 | Credential Access |
| FTP Auth Attempt | T1110.001 | Credential Access |
| SQL Injection | T1190 | Initial Access |
| Path Traversal | T1190 | Initial Access |
| FTP Anonymous Access | T1078 | Defense Evasion |
| Web Scanner | T1595.002 | Reconnaissance |
| SSH Probe / HTTP Probe | T1595.001 | Reconnaissance |

---

## 4. The pipeline, step by step

`pipeline.on_event()` is the single entry point for every observation,
regardless of whether a honeypot or the simulator produced it.

### Step 1 — Enrich

`enrichment.enrich()` resolves geography and attaches intel tags.

GeoIP resolution (`geoip.py`) is tiered, cheapest first:

1. **Curated atlas** — 26 known demo/seed attacker IPs with hand-set city
   coordinates. Instant, no network.
2. **Loopback / RFC1918** — returned as `Private / Lab`, no coordinates.
3. **Process cache** — a plain dict, never evicted.
4. **`ip-api.com`** over plaintext HTTP with a 4-second timeout.
5. **Failure** — `{country: "Unknown", city: "", latitude: None, longitude: None}`.
   A failed lookup never blocks ingestion; the event is stored without
   coordinates and simply does not appear on the map.

Intel tags are seeded local sets: `tor` (4 known exit nodes), `known_scanner`
(6 addresses), and `vpn` (two /24 ranges). These stand in for a MISP or OTX feed.

### Step 2 — Escalate repeat offenders

Before scoring, the running hit count for the IP can raise the severity the
sensor assigned:

- 10 or more hits (`REPEAT_ESCALATE_HITS`) forces **critical**
- 5 or more hits (`REPEAT_MEDIUM_MIN_HITS`) lifts **low** to **medium**

This is what makes persistence visible. A single low-severity HTTP probe is
noise; the same host probing forty times is a scanner working through a list.

### Step 3 — Score the risk

`detection.risk_score()` produces a 0–100 integer, clamped at both ends:

```
base            severity: low 15 · medium 35 · high 60 · critical 85
+ persistence   min(hits × 2, 25)
+ lateral       +15 if ≥2 distinct ports in the last hour
                +10 more if ≥3
+ reputation    +15 known_scanner · +12 tor · +5 vpn
+ origin        +5 if Russia, China, Iran or North Korea
```

The port-count component is the interesting one. An attacker touching SSH *and*
HTTP *and* FTP within an hour is sweeping for any way in, which is a materially
different threat from a single-service brute force — so breadth is scored
separately from volume.

The country bump is a crude prior reflecting honeypot traffic distribution. It
is worth 5 points out of 100 and is deliberately too small to change a triage
decision on its own.

### Step 4 — Fingerprint and deduplicate

This is the core anti-alert-fatigue mechanism:

```13:23:backend/correlation.py
def fingerprint(ip: str, threat_type: str, ts: str | None = None) -> str:
    """Dedup key: ip + threat + hour bucket → 200 probes become 1 alert."""
```

The key is `sha256(ip | threat_type | YYYYMMDDHH)` truncated to 24 hex
characters. Every event computes one and looks for an existing **open** alert
with the same value:

- **Match** → `bump_alert()` increments `event_count`, refreshes `last_seen`,
  raises severity and risk if the new event is worse, and merges the technique
  and tag lists. No new alert.
- **No match** → a new alert is created in status `new`.

The hour bucket is what makes this self-healing. A sustained attack rolls into a
fresh alert every hour, so the queue shows "still happening" rather than one
ancient alert with a five-figure counter. Only *open* alerts are matched, so
resolving an alert lets the next event legitimately re-open the issue.

Before any of this, the event is checked against `suppression_rules`. A
suppressed event is stored, flagged, published to the UI so the analyst can see
it was caught, and then dropped — it never creates or bumps an alert.

### Step 5 — Correlate into campaigns

`correlate_campaign()` looks for structure across alerts. A campaign opens when
either condition holds:

- **Multi-port**: the same IP has hit **2 or more distinct ports within 1 hour**
- **Subnet burst**: **3 or more distinct IPs in the same /24 within 2 hours**

Multi-port catches one host sweeping your services. Subnet burst catches a
botnet segment or a single operator rotating addresses inside a range — the
individual IPs each look unremarkable, and only the /24 grouping reveals them.

An existing active campaign for that IP is updated (union of IPs, ports and
techniques; severity takes the max; risk takes the max) rather than duplicated.
New campaigns open at severity `high`, or `critical` if the triggering event was.

### Step 6 — Publish and auto-respond

Alert first, then event, then campaign, then a `stats_hint` pulse. Alert-before-
event is deliberate: the triage UI keys rows off alerts, so publishing the event
first would render a row referencing an alert the client has not yet seen.

Finally, if the IP has reached 10 hits and is not whitelisted, the
`auto_contain_repeat_offender` playbook fires and blocks it for 12 hours.

---

## 5. Alerts and their lifecycle

`alerts.py` implements the state machine. Every transition writes to
`audit_log`, and every transition publishes over SSE.

```
   new ──ack──▶ acked ──investigate──▶ investigating ──escalate──▶ escalated
    │             │                          │                          │
    └─────────────┴──────────┬───────────────┴──────────────────────────┘
                             ▼
                 resolved  or  false_positive
```

`acked_at` and `resolved_at` are timestamps, not booleans, because MTTA and MTTR
are computed from the gap between them and `first_seen`.

Escalation is not just a status change: it also forces severity to `critical`
and reassigns to `soc-lead`, so escalating hands the alert to someone rather
than merely flagging it.

Marking an alert **false positive** does more than close it. It writes a
`suppression_rules` row keyed on the fingerprint with a 24-hour expiry, so
matching events stop producing alerts. That is the feedback loop that makes a
noisy detection quiet down instead of being dismissed repeatedly.

---

## 6. Cases and SLAs

`cases.py` handles incidents that outlive a single alert. A case bundles alert
IDs and an optional campaign, carries an assignee and an append-only note list,
and has `sla_due_at` set at creation from a minutes offset.

SLA breach is computed at read time by comparing `sla_due_at` against now — no
background job marks cases late, so the clock is always accurate and there is no
state to drift.

---

## 7. Containment, and the honesty problem

This is the part of the system most worth understanding, because the obvious
implementation lies to you.

`blocker.py` keeps **two** sets:

- `_intended` — every IP we have decided to block
- `_enforced` — every IP where an OS firewall rule was actually created

`block_ip()` shells out to `netsh advfirewall firewall add rule` on Windows or
`iptables -A INPUT -s <ip> -j DROP` on Linux, and returns
`{intended, enforced, error}` reflecting what really happened. Both commands
need elevated privileges. When they fail, the block is still recorded — but it
is **never reported as enforced**.

That distinction is carried all the way through:

- `blocklist.enforced` is a real column in SQLite
- the audit entry appends `[NOT ENFORCED: <reason>]`
- `GET /api/health` reports firewall capability
- the UI shows a per-row `firewall` / `recorded only` chip and a warning banner

`enforcement_status()` probes capability by creating and deleting a throwaway
rule against `203.0.113.255` — an RFC 5737 TEST-NET address that cannot belong
to anyone. The probe is necessary because merely *reading* firewall state
succeeds without privileges and would report a false positive. The result is
cached for the process lifetime.

A `WHITELIST` of `127.0.0.1`, `::1` and `localhost` guards against
self-containment, and `is_valid_ip()` rejects malformed input before it ever
reaches a shell command — the API returns 422 for anything that is not a valid
address.

**Blocks expire.** `actions.sweep_expired()` runs every 60 seconds from a
lifespan task, releasing any block whose `expires_at` has passed and publishing
an `expiry_release` action. Default durations are 24 hours for a manual block,
12 for auto-containment, and 24 for the recon-burst playbook.

**Restart behaviour.** OS firewall rules do not survive a host reboot, and the
in-memory sets do not survive a process restart, so `sync_from_db()` runs at
startup and re-applies rules for every active block. Nothing is assumed enforced
until that re-application actually succeeds — which is why an unprivileged start
logs "N blocklist entries restored but none could be enforced".

---

## 8. Playbooks

`playbooks.py` bundles multi-step responses so an analyst performs one action
instead of six. Every run is audited.

| ID | Steps |
|---|---|
| `contain_ip` | Block at firewall → blocklist row → audit |
| `escalate_critical` | Escalate alert → open critical case for `soc-lead` with a 30-minute SLA |
| `recon_burst_response` | Contain IP for 24h → escalate *all* open alerts for that IP → open a case linking them |
| `false_positive_cleanup` | Mark FP → suppress fingerprint for 24h |
| `auto_contain_repeat_offender` | System-only: contain for 12h. Fired by the pipeline at 10 hits, not exposed in the UI list. |

---

## 9. Real-time delivery

`GET /api/stream` returns a `text/event-stream`. Each client gets its own
`asyncio.Queue` with `maxsize=200`, registered in a process-level set:

```23:23:backend/pipeline.py
_subscribers: set[asyncio.Queue] = set()
```

`publish()` wraps the payload in `{type, data, seq}` and pushes to every queue.
A full queue has its oldest item dropped to make room — a slow client degrades
to missing frames rather than applying backpressure to the pipeline or leaking
memory. Queues that fail entirely are discarded.

Message types: `event`, `alert`, `campaign`, `case`, `action`, `simulator`,
`stats_hint`.

Two framing details: the stream opens with a `hello` frame carrying the API
version, so a client can tell "connected" from "connected but idle". And if
nothing is published for 12 seconds it emits a `ping`, which keeps intermediate
proxies from treating the idle connection as dead and closing it.

The stream sets `X-Accel-Buffering: no` and `Cache-Control: no-cache,
no-transform`, which is what stops reverse proxies and CDNs from buffering the
stream into uselessness.

**This is the single biggest constraint on deployment.** The subscriber set is
process memory, so the API must run as exactly one worker. Two workers means
half your clients never receive the events published by the other. See
[`DEPLOYMENT.md`](./DEPLOYMENT.md).

Authentication for this endpoint is a `?key=` query parameter, because the
browser `EventSource` API cannot set custom headers. Query strings get logged by
proxies and land in browser history — a real deployment would use a short-lived
signed token here.

---

## 10. The ambient simulator

`live_attacks.py` keeps the dashboard from ever being empty. It calls the exact
same `on_event()` the honeypots call, so simulated traffic is enriched, scored,
deduplicated, correlated and contained by identical logic — there is no parallel
code path and no special casing beyond the `source` tag.

It draws from an 18-address attacker pool and nine scenarios covering all four
sensor ports, with payloads that embed `src={ip}` or `X-Forwarded-For: {ip}` so
the loopback IP-resolution path geolocates them properly.

The loop is not a flat random walk. A tick counter shapes it:

| Tick | Behaviour |
|---|---|
| every 14th | **Campaign burst** — one of three designated IPs fires 3 different scenarios across ports 2222/8080/2121, 0.15s apart. This reliably trips the multi-port campaign rule. |
| every 9th | **Repeat-offender hammer** — `185.220.101.45` hits SSH again, driving its hit count up so escalation and auto-containment fire. |
| otherwise | Random attacker, random scenario. |

That structure exists so the demo exercises correlation and auto-response rather
than just producing a flat stream of unrelated events.

Timing is a 2.5-second startup delay, then `SENTINEL_LIVE_INTERVAL` (1.6s) with
`random.uniform(-0.6, 0.9)` jitter so it reads as organic rather than metronomic.

**Note:** seven of the eighteen simulator IPs are *not* in the GeoIP atlas, so
they resolve through `ip-api.com` on first sight and are then cached in-process.
This is why a fresh start logs a handful of outbound GeoIP calls before settling.

Pause and resume are handled by an `asyncio.Event`:

```python
_running = asyncio.Event()
_running.set()
```

The generator loop awaits it each iteration, so clearing the event parks the
loop cheaply with no polling. `POST /api/simulator` flips it, writes an audit
entry, and broadcasts a `simulator` SSE message so every open tab agrees.
Honeypot sensors keep ingesting the whole time.

---

## 11. Provenance — what is real

Every event and alert carries a `source` column, and the UI badges it:

| Value | Meaning | Badge |
|---|---|---|
| `sensor` | A honeypot actually received this | `REAL` |
| `simulator` | The built-in generator produced it | `SIM` |
| `mixed` | An alert fed by both kinds of event | `MIX` |
| `unlabelled` | Written before provenance tracking existed | `—` |

`mixed` is applied by `bump_alert()` when an alert accumulates events from more
than one source. `unlabelled` is deliberately not claimed as either — rows that
predate the feature are not retroactively guessed at.

`GET /api/stats` breaks the counts down, and `GET /api/events?source=sensor`
filters to genuinely observed traffic only.

---

## 12. Data model

Nine tables in SQLite (`database.py`), running in WAL mode with a thread-local
connection. All timestamps are naive UTC ISO-8601 strings, compared as strings —
`timeutil.py` exists to keep that representation byte-identical while avoiding
the deprecated `datetime.utcnow()`.

| Table | Purpose | Notable columns |
|---|---|---|
| `events` | Every observation, raw | `payload` (300 char cap), `raw_hash`, `alert_id`, `risk_score`, `mitre_technique`, `intel_tags`, `source` |
| `ip_counts` | Running hit tally per IP | `hits`, `last_seen` — drives repeat-offender escalation |
| `alerts` | Deduplicated, triageable | `fingerprint`, `event_count`, `status`, `acked_at`, `resolved_at`, `campaign_id`, `source` |
| `campaigns` | Correlated multi-alert activity | `ips`, `ports`, `techniques` (JSON arrays), `alert_count` |
| `cases` | Incident records | `alert_ids` (JSON), `sla_due_at`, `notes` (JSON), `close_reason` |
| `blocklist` | Containment state | `active`, `expires_at`, **`enforced`** |
| `audit_log` | Append-only action record | `actor`, `action`, `target`, `detail` |
| `suppression_rules` | FP-driven quieting | `kind` (`fingerprint`, `ip` or `threat_type`), `value`, `expires_at` |

Plus `analysts`, a three-row fixed table (`alice`, `bob`, `soc-lead`).

Fourteen indexes cover the hot paths: events by timestamp/IP/severity/source,
alerts by fingerprint/status/IP, and the active blocklist.

JSON-in-TEXT columns are a deliberate SQLite trade-off — they keep the schema
flat at the cost of not being queryable. Postgres with real array columns is the
upgrade path.

---

## 13. API surface

Every route requires the `X-API-Key` header except `/api/health` and
`/api/stream` (which uses `?key=`). The acting analyst is the self-asserted
`X-Analyst` header, defaulting to `alice`.

**Observation** — `GET /api/events` (filters: `limit`, `severity`, `ip`,
`source`), `/api/stats`, `/api/metrics`, `/api/geo/points`, `/api/export`,
`/api/health`, `/api/analysts`

**Alert triage** — `GET /api/alerts`, `GET /api/alerts/{id}`, and `POST` to
`/ack`, `/assign`, `/investigate`, `/escalate`, `/resolve`, `/false-positive`

**Cases** — `GET`/`POST /api/cases`, `GET`/`PATCH /api/cases/{id}`,
`POST /api/cases/{id}/notes`

**Campaigns** — `GET /api/campaigns`, `GET /api/campaigns/{id}`

**Investigation** — `GET /api/investigate/{ip}` returns the full pivot: timeline,
payloads, related alerts, campaign membership

**Response** — `GET`/`POST /api/blocklist`, `DELETE /api/blocklist/{ip}`,
`GET /api/playbooks`, `POST /api/playbooks/{id}/run`, `GET /api/audit`,
`POST /api/simulator`

**Real-time** — `GET /api/stream`

Interactive docs are served at `/api/docs`.

---

## 14. Frontend

A Vite/React 19 SPA. State is centralised in one context provider,
`hooks/useSoc.jsx`, which owns the `EventSource` connection, holds alerts,
events, stats, campaigns and geo points, and exposes the mutation helpers. Views
are presentational and read from that context, so a single SSE frame updates
every view at once.

| View | Purpose |
|---|---|
| Overview | Bento dashboard — KPIs, world map, live feed, ATT&CK heat, 24h volume |
| Alert Queue | Triage board with filters and keyboard shortcuts (`a` `i` `e` `r` `f`) |
| Investigate | IP pivot: timeline, payloads, related alerts, campaign, run playbook |
| Cases | Incident list with SLA countdown and notes |
| Response | Blocklist manager, playbook runner, audit feed |
| Metrics | MTTA/MTTR, false-positive rate, auto vs manual containment |

`components/ThreatMap.jsx` renders an equirectangular world map from
`assets/worldPaths.js` — 177 country paths pre-projected at build time by
`scripts/gen-world.mjs`, which also unwraps geometry crossing the antimeridian
so features near ±180° do not streak across the map. Attack origins are plotted
by linear lat/lon projection with animated arcs to the sensor.

The strip below the top bar measures how many entries fit and hides the
remainder rather than clipping one mid-word, re-measuring on resize.

---

## 15. Configuration

| Variable | Default | Effect |
|---|---|---|
| `SENTINEL_API_KEY` | `sentinel-dev-key` | Value required in `X-API-Key` |
| `SENTINEL_DB` | `sentinel.db` | SQLite file path |
| `SENTINEL_ORIGINS` | localhost:5173 variants | Comma-separated CORS allowlist |
| `SENTINEL_LIVE_ATTACKS` | `1` | `0`/`false`/`off` disables the simulator entirely |
| `SENTINEL_LIVE_INTERVAL` | `1.6` | Seconds between simulated events |
| `SSH_PORT` / `HTTP_PORT` / `FTP_PORT` / `TELNET_PORT` | 2222 / 8080 / 2121 / 2323 | Honeypot bind ports |
| `VITE_SENTINEL_API` | `http://127.0.0.1:8000` | API base — inlined at **build** time |
| `VITE_SENTINEL_KEY` | `sentinel-dev-key` | API key — inlined at **build** time |

Two thresholds are compile-time constants in `config.py`:
`REPEAT_ESCALATE_HITS = 10` and `REPEAT_MEDIUM_MIN_HITS = 5`.

---

## 16. In-memory state

Four things live in process memory and do not survive a restart. All four are
also reasons the API cannot be horizontally scaled as written.

| What | Where | Consequence of a restart | Consequence of two instances |
|---|---|---|---|
| SSE subscriber queues | `pipeline._subscribers` | Clients reconnect automatically | **Events reach only the instance that published them** |
| Broadcast replay buffer | `pipeline._broadcast` (500 items) | Recent history lost | Divergent buffers |
| GeoIP cache | `geoip._cache` | Re-fetched, briefly slower ingest | Duplicated lookups, hits the rate limit sooner |
| Firewall intent/enforced sets | `blocker._intended`, `_enforced` | Rebuilt from SQLite at startup | Two views of firewall state |

The durable state — events, alerts, cases, blocklist, audit — is all in SQLite
and survives restarts intact.

---

## 17. Known limits

Stated plainly, because they define the boundary between this and a production
sensor:

1. **The API key is not authentication.** Vite inlines it into the JavaScript
   bundle, so anyone who loads the dashboard can read it and call any endpoint.
2. **One worker only.** SSE fan-out is in-process.
3. **GeoIP is the ingest bottleneck.** `ip-api.com` allows 45 requests/minute
   over plaintext HTTP. Under load with uncached IPs, roughly a third of events
   are dropped and API latency rises to several seconds. A bundled MaxMind
   GeoLite2 database removes the network hop entirely.
4. **No retention policy.** The events table grows without bound.
5. **`X-Analyst` is self-asserted.** Any client can claim to be any analyst, so
   the audit log records intent rather than proven identity.
6. **Detection is substring matching**, not a Sigma engine. It is honest about
   the traffic honeypots actually see, but it is trivially evadable by anything
   that encodes its payload.
