# Deploying Sentinel SOC

Sentinel is two deployable units with very different hosting needs:

| Unit | What it is | Where it can run |
|---|---|---|
| `frontend/` | Static Vite/React SPA — HTML, CSS, JS | Any static host. **Vercel is a good fit.** |
| `backend/` | Long-lived FastAPI process + raw TCP listeners + SQLite | A container host or VPS. **Not Vercel.** |

The short version: put the dashboard on Vercel, put the API on a container host,
and point the first at the second with one environment variable.

---

## Why the backend cannot run on Vercel

This is not a configuration problem, so it is worth being precise about. Vercel
runs your code as functions invoked per HTTP request. Five things in Sentinel's
design are incompatible with that model, and four of them are fatal.

**1. The honeypots cannot exist.** `honeypots.py` calls `asyncio.start_server()`
to bind TCP ports 2222, 8080, 2121 and 2323 and speak SSH, HTTP, FTP and Telnet
banners at whoever connects. A Vercel function only ever receives an HTTP request
that the platform has already routed to it; there is no way to bind a listening
socket on an arbitrary port. The sensor layer — the part that makes this a
honeypot project rather than a dashboard — has nowhere to live.

**2. Real-time updates would silently stop working.** SSE subscribers are held in
a module-level set in the API process:

```23:23:backend/pipeline.py
_subscribers: set[asyncio.Queue] = set()
```

`publish()` walks that set and pushes to each queue. This only works because the
code that creates an event and the code holding the open stream are in the same
process. On Vercel they would be different function instances with separate
memory, so events would be published into a set that the streaming client is not
in. The dashboard would connect successfully and then never receive anything.
Fixing this means replacing the in-memory set with Redis pub/sub.

**3. The database resets constantly.** `sentinel.db` is a SQLite file on local
disk. Vercel's filesystem is read-only apart from `/tmp`, and `/tmp` is per
instance and discarded when that instance is recycled. Alerts, cases, audit log
and blocklist would all vanish unpredictably, and two concurrent instances would
disagree about the state of the world.

**4. Background work would never run.** The ambient attack simulator and the
block-expiry loop are `asyncio` tasks started in the FastAPI lifespan and
expected to run forever. Serverless has no process between requests, so neither
loop would tick.

**5. Containment could never be enforced.** `blocker.py` shells out to `netsh
advfirewall` or `iptables`. Those need a privileged host you control.

There is also a duration ceiling — Vercel functions cap at 300 seconds on Hobby
and 800 on Pro — so even a Redis-backed SSE stream would be severed every few
minutes. That one is survivable, since `EventSource` reconnects automatically.
Items 1 through 4 are not.

**What a Vercel-hosted backend would actually look like:** no honeypots, no live
updates, no ambient traffic, and a database that empties itself at random. That
is strictly worse than showing the dashboard against a real API.

---

## Recommended topology

```
        ┌──────────────────────┐        HTTPS + SSE       ┌───────────────────────┐
        │  Vercel (free)       │ ───────────────────────▶ │  Fly.io / Oracle VM   │
        │  frontend/ (static)  │                          │  backend/ (Docker)    │
        └──────────────────────┘                          └───────────────────────┘
```

| Host | Card? | Notes (as of Aug 2026) |
|---|---|---|
| **Vercel** (frontend only) | no | Already deployed. Cannot run this API. |
| **Koyeb** | yes | Starter closed to new signups after the Mistral acquisition. |
| **Hugging Face Docker Spaces** | yes (PRO) | Static Spaces are free; Docker/Gradio require PRO. |
| **Fly.io** | yes | Best managed option if you will pay a few dollars. |
| **Oracle Always Free** | ID check only | Only remaining 24/7 free VM with a real disk. |
| Local API + Vercel UI | no | Works on *your* machine while `start.ps1` is running. |

---

## Step 1 — Deploy the backend (Oracle Always Free)

Oracle is the only remaining 24/7 free host with a real disk and no monthly
bill — they take a card for identity and then do not charge Always Free
resources. Home region is permanent; pick one close to you
(`eu-frankfurt-1` or `eu-amsterdam-1` from Eastern Europe).

### Account

1. Sign up at [https://signup.cloud.oracle.com](https://signup.cloud.oracle.com).
2. Use a real phone number and card. Stay on **Always Free** — do not upgrade
   to Pay As You Go unless you intend to.
3. Wait for the email that the tenancy is ready (can take a few minutes).

### Network (do this before the VM)

Hamburger menu → **Networking** → **Virtual Cloud Networks** → **Start VCN
Wizard** → **Create VCN with Internet Connectivity**. Accept defaults.

Then **VCN → public subnet → Default Security List → Add Ingress Rules**.
Add three TCP rules, Source CIDR `0.0.0.0/0`:

| Destination port | Why |
|---|---|
| 22 | SSH |
| 80 | Let's Encrypt + Caddy |
| 443 | HTTPS for the API (required so the Vercel page is not mixed-content blocked) |

Do **not** open 2222/8080/2121/2323. Sensors stay internal.

### Instance

**Compute → Instances → Create instance**

| Field | Value |
|---|---|
| Name | `sentinel` |
| Image | Canonical Ubuntu 24.04 (ARM) |
| Shape | **VM.Standard.A1.Flex** — Always Free Ampere |
| OCPUs / RAM | **1 / 6 GB** (enough; more likely to have capacity than 4/24) |
| SSH keys | **Generate** and save both files. You cannot recover the private key. |
| Networking | the VCN you just created, assign a public IPv4 |

If creation fails with *Out of capacity*, retry a different **Availability
domain**, drop to 1 OCPU / 6 GB if you tried more, or wait and retry. Ampere
stock is the well-known catch.

SSH in (PowerShell, from the folder that holds the key):

```powershell
ssh -i .\ssh-key-xxxx.key ubuntu@<PUBLIC_IP>
```

### On the VM

Copy the repo onto the box (from your laptop, repo root):

```powershell
scp -i .\ssh-key-xxxx.key -r backend docker-compose.oracle.yml deploy ubuntu@<PUBLIC_IP>:~/sentinel
```

Then on the VM:

```bash
cd ~/sentinel
chmod +x deploy/oracle/setup.sh
./deploy/oracle/setup.sh
```

That installs Docker, opens iptables for 80/443, builds the API, and puts
Caddy + Let's Encrypt in front of `https://<PUBLIC_IP>.sslip.io` so browsers
will allow the HTTPS Vercel dashboard to call it.

Confirm:

```bash
curl -fsS https://<PUBLIC_IP>.sslip.io/api/health
```

Paste that URL back here. I will set `VITE_SENTINEL_API` on Vercel, put the
API key in the frontend build, and redeploy the dashboard.

---

### Koyeb (not available to new accounts)

One free web service, 512 MB RAM, HTTPS. It scales to zero after **one hour
without HTTP traffic**, and the disk goes with it. Sentinel handles that by
seeding 7 days of demo history whenever it boots onto an empty database, then
running the simulator. A recruiter who hits a cold instance waits ~20–40s and
then sees a full SOC, not an empty queue.

Honeypot TCP ports are not published — only HTTP :8000 is. Sensors still bind
inside the container; they just never see outside traffic.

1. Create a free account at [app.koyeb.com](https://app.koyeb.com).
2. Install the CLI (Windows: grab `koyeb-cli_windows_amd64.zip` from the
   [GitHub releases](https://github.com/koyeb/koyeb-cli/releases)).
3. `koyeb login` in a normal PowerShell window (not Cursor's).
4. From `backend/`:

```powershell
koyeb deploy . sentinel-soc/api `
  --archive-builder docker `
  --instance-type free `
  --regions fra `
  --ports 8000:http `
  --routes /:8000 `
  --checks 8000:http:/api/health `
  --checks-grace-period 8000=40 `
  --env PORT=8000 `
  --env SENTINEL_SEED_ON_EMPTY=1 `
  --env SENTINEL_LIVE_ATTACKS=1 `
  --env SENTINEL_DB=/data/sentinel.db `
  --env SENTINEL_ORIGINS=https://sentinel-soc-sand.vercel.app `
  --env SENTINEL_API_KEY=change-me
```

Wait until `koyeb service get sentinel-soc/api` shows `HEALTHY`. The public URL
looks like `https://<name>-<hash>.koyeb.app`. Confirm:

```bash
curl https://<that-url>/api/health
```

Then rebuild the Vercel frontend with `VITE_SENTINEL_API` set to that URL
(see Step 2). Changing either Vite variable requires a frontend **rebuild**,
not a restart.

**What sleep looks like.** After an hour with no visitors the instance stops.
The next request pays a cold start: empty disk → seed → simulator. In-flight
SSE connections die with the instance; the dashboard reconnects on its own.
Analyst actions taken during the previous wake (acks, cases, blocks) are gone.

### Fly.io

From the repository root:

```bash
fly launch --dockerfile backend/Dockerfile --no-deploy
```

Answer *no* to adding a database — Sentinel uses SQLite on a volume. Then create
the volume and set secrets:

```bash
fly volumes create sentinel_data --size 1
fly secrets set SENTINEL_API_KEY="$(openssl rand -hex 24)"
fly secrets set SENTINEL_DB=/data/sentinel.db
```

Edit the generated `fly.toml` so the database lands on the volume, only one
instance ever runs, and the honeypot ports are exposed:

```toml
[env]
  SENTINEL_LIVE_ATTACKS = "1"

[mounts]
  source      = "sentinel_data"
  destination = "/data"

# Exactly one instance: SSE fan-out is in-process, so a second machine
# would serve clients that never receive events.
[http_service]
  internal_port        = 8000
  force_https          = true
  auto_stop_machines   = false
  min_machines_running = 1

[[services]]                      # SSH honeypot
  internal_port = 2222
  protocol      = "tcp"
  [[services.ports]]
    port = 2222

[[services]]                      # HTTP honeypot
  internal_port = 8080
  protocol      = "tcp"
  [[services.ports]]
    port = 8080

[[services]]                      # FTP honeypot
  internal_port = 2121
  protocol      = "tcp"
  [[services.ports]]
    port = 2121

[[services]]                      # Telnet honeypot
  internal_port = 2323
  protocol      = "tcp"
  [[services.ports]]
    port = 2323
```

Deploy and confirm:

```bash
fly deploy
fly scale count 1          # never more than one
curl https://<your-app>.fly.dev/api/health
```

`auto_stop_machines = false` matters. If Fly suspends the machine when idle, the
simulator stops and the first visitor gets a cold start.

### Render or Railway

Point the service at `backend/Dockerfile`, attach a persistent disk mounted at
`/data`, set `SENTINEL_DB=/data/sentinel.db`, and **fix the instance count at
one**. The honeypot ports will not be publicly reachable, so the sensor layer
only sees traffic you generate from inside the container. Set
`SENTINEL_LIVE_ATTACKS=1` so the dashboard still has something to show.

---

### Seeding the database

`seed_data.py` is **not** run at startup, so a fresh volume means a completely
empty dashboard — no history, no metrics, MTTA/MTTR undefined. The simulator
starts filling it immediately, but there is no 7-day history to plot.

To get realistic depth on a new deployment, run the seeder once against the
volume:

```bash
fly ssh console -C "python /app/seed_data.py"
```

Note that the seeder **wipes the SOC tables first**, so only ever run it on a
fresh deployment.

---

## Step 2 — Deploy the frontend to Vercel

The SPA config already lives at `frontend/vercel.json` — static build, a rewrite
so client-side routes survive a hard refresh, and immutable caching for hashed
assets.

From the `frontend/` directory:

```bash
vercel link
vercel env add VITE_SENTINEL_API production   # https://<your-app>.fly.dev
vercel env add VITE_SENTINEL_KEY production   # the SENTINEL_API_KEY you generated
vercel --prod
```

Both variables are read at **build** time by Vite, so changing either requires a
redeploy, not just a restart.

## Step 3 — Wire CORS

The backend rejects browser origins it does not know. Give it the Vercel URL:

```bash
fly secrets set SENTINEL_ORIGINS="https://<your-project>.vercel.app"
```

Use a comma-separated list to allow a custom domain too. Vercel preview
deployments get unique URLs, so they will fail CORS unless you add them
explicitly — expect previews to show a disconnected dashboard.

## Step 4 — Verify

1. `GET https://<backend>/api/health` returns `status: ok` and reports
   `simulator_running` and `firewall_enforcement`.
2. Load the Vercel URL. The pill in the top bar should read **LIVE**, not
   disconnected.
3. Watch the ticker for a few seconds — entries appearing means SSE is connected
   through the CDN, which is the piece most likely to break.
4. Expect the amber *"Containment not enforced"* banner unless the container has
   `NET_ADMIN`. That is the honest-reporting behaviour working, not a fault.

---

## Deployment gotchas

**Never run more than one backend instance.** Both SSE fan-out and the SQLite
file assume a single process. A second replica produces a dashboard that connects
but stays silent, plus two divergent databases. Disable autoscaling explicitly.

**The API key is public.** Vite inlines `VITE_SENTINEL_KEY` into the bundle, so
anyone who loads the dashboard can read it and call the API directly, including
the containment endpoints. Treat the deployed instance as world-writable. Real
authentication is item 3 on the production roadmap in `README.md`.

**SSE through a CDN.** The backend already sends `X-Accel-Buffering: no` and
`Cache-Control: no-transform`, which is what stops proxies from buffering the
stream. If the ticker stays empty while `/api/stats` works, buffering is the
first thing to check.

**Unbounded growth.** No retention policy exists. With the simulator at its
default 1.6-second interval that is roughly 54,000 events per day. Size the
volume accordingly or turn the simulator off for a long-running deployment.

**GeoIP rate limit.** `ip-api.com` allows 45 requests/minute. The simulator draws
from a curated pool that is mostly cached locally, but real honeypot traffic will
hit the limit and slow ingest noticeably.
