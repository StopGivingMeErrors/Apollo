"""Seed realistic SOC history: events, alerts, campaigns, cases, blocks, audit."""
from __future__ import annotations

import json
import random
import sqlite3
from datetime import timedelta

from config import DB_PATH
from detection import mitre_for, risk_score
from enrichment import intel_tags_for
from geoip import ATTACKER_ATLAS, COUNTRY_CENTROID
from timeutil import utcnow


def _coords(ip: str, country: str) -> tuple[float | None, float | None, str]:
    atlas = ATTACKER_ATLAS.get(ip)
    if atlas:
        return atlas["latitude"], atlas["longitude"], atlas.get("city", "")
    lat, lon = COUNTRY_CENTROID.get(country, (None, None))
    return lat, lon, ""


IPS = [
    ("185.220.101.45", "Germany"),
    ("194.165.16.72", "Russia"),
    ("45.142.212.100", "Netherlands"),
    ("103.21.244.0", "China"),
    ("191.96.249.55", "Brazil"),
    ("80.82.77.139", "Germany"),
    ("162.247.74.201", "United States"),
    ("109.201.133.195", "Russia"),
    ("221.194.47.242", "China"),
    ("41.206.188.185", "Iran"),
    ("179.43.128.16", "Romania"),
    ("5.188.206.26", "Russia"),
    ("92.63.197.48", "Ukraine"),
    ("193.32.162.157", "Netherlands"),
    ("61.177.173.18", "China"),
    ("198.51.100.10", "United States"),
    ("203.0.113.50", "Australia"),
    ("203.0.113.51", "Australia"),
    ("203.0.113.52", "Australia"),
]

THREATS = [
    ("SSH Brute Force", "critical", 2222),
    ("SSH Probe", "medium", 2222),
    ("SQL Injection", "critical", 8080),
    ("Web Scanner", "high", 8080),
    ("HTTP Probe", "low", 8080),
    ("Path Traversal", "high", 8080),
    ("FTP Auth Attempt", "medium", 2121),
    ("FTP Anonymous Access", "medium", 2121),
    ("Telnet Login Attempt", "high", 2323),
]

ANALYSTS = ["alice", "bob", "soc-lead"]


def seed(days: int = 7, events_per_day: int = 100) -> None:
    # Import after path setup
    from database import init_db

    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Wipe SOC tables for clean demo (keep schema)
    for table in (
        "events", "ip_counts", "alerts", "campaigns", "cases",
        "blocklist", "audit_log", "suppression_rules",
    ):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()

    now = utcnow()
    alert_map: dict[str, int] = {}  # fingerprint -> alert id
    event_count = 0

    for day in range(days):
        for _ in range(events_per_day):
            hour = random.choices(
                range(24),
                weights=[2, 1, 1, 1, 2, 3, 5, 8, 10, 12, 12, 11, 10, 11, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3],
                k=1,
            )[0]
            ts_dt = now - timedelta(days=day, hours=now.hour - hour,
                                    minutes=random.randint(0, 59),
                                    seconds=random.randint(0, 59))
            ts = ts_dt.isoformat(timespec="seconds")

            # Prefer repeat patterns so fingerprints collapse into fewer alerts
            if random.random() < 0.55:
                ip, country = random.choice(IPS[:6])
                threat, severity, port = random.choice(THREATS[:5])
            elif random.random() < 0.35:
                ip, country = random.choice(IPS[:5])
                threat, severity, port = random.choice(THREATS)
            else:
                ip, country = random.choice(IPS)
                threat, severity, port = random.choice(THREATS)
            tags = intel_tags_for(ip)
            mitre = mitre_for(threat)
            hits_est = random.randint(1, 20)
            score = risk_score(
                severity=severity,
                hits=hits_est,
                port_count=random.randint(1, 3),
                intel_tags=tags,
                country=country,
            )
            # Day-bucket fingerprint for seed history (live pipeline still uses hour)
            fp = f"{ip}|{threat}|{ts_dt.strftime('%Y%m%d')}"
            fp = __import__("hashlib").sha256(fp.encode()).hexdigest()[:24]
            lat, lon, city = _coords(ip, country)

            cur = conn.execute(
                """
                INSERT INTO events
                  (timestamp, ip, port, payload, threat_type, severity, country, city,
                   latitude, longitude, mitre_technique, risk_score, raw_hash, intel_tags,
                   source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'simulator')
                """,
                (
                    ts, ip, port, "", threat, severity, country, city,
                    lat, lon, mitre["technique"], score, fp[:16], json.dumps(tags),
                ),
            )
            event_id = cur.lastrowid
            event_count += 1

            conn.execute(
                """
                INSERT INTO ip_counts (ip, hits, last_seen)
                VALUES (?, 1, ?)
                ON CONFLICT(ip) DO UPDATE SET hits = hits + 1, last_seen = excluded.last_seen
                """,
                (ip, ts),
            )

            if fp in alert_map:
                aid = alert_map[fp]
                conn.execute(
                    """
                    UPDATE alerts SET event_count = event_count + 1, last_seen = ?,
                      risk_score = CASE WHEN risk_score > ? THEN risk_score ELSE ? END
                    WHERE id = ?
                    """,
                    (ts, score, score, aid),
                )
            else:
                # Status distribution for realism — most historical alerts closed
                roll = random.random()
                if day >= 1:
                    if roll < 0.45:
                        status = "resolved"
                    elif roll < 0.60:
                        status = "false_positive"
                    elif roll < 0.72:
                        status = "acked"
                    elif roll < 0.82:
                        status = "investigating"
                    elif roll < 0.90:
                        status = "escalated"
                    else:
                        status = "new"
                else:
                    # Recent day keeps more open work
                    if roll < 0.25:
                        status = "new"
                    elif roll < 0.45:
                        status = "acked"
                    elif roll < 0.60:
                        status = "investigating"
                    elif roll < 0.72:
                        status = "escalated"
                    elif roll < 0.88:
                        status = "resolved"
                    else:
                        status = "false_positive"

                assignee = random.choice(ANALYSTS) if status != "new" else ""
                acked_at = (ts_dt + timedelta(minutes=random.randint(2, 40))).isoformat(timespec="seconds") if status != "new" else None
                resolved_at = None
                if status in ("resolved", "false_positive"):
                    resolved_at = (ts_dt + timedelta(minutes=random.randint(30, 180))).isoformat(timespec="seconds")

                title = f"{threat} from {ip}"
                cur = conn.execute(
                    """
                    INSERT INTO alerts
                      (fingerprint, title, severity, status, assignee, ip, threat_type,
                       mitre_techniques, event_count, first_seen, last_seen, acked_at,
                       resolved_at, risk_score, country, intel_tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fp, title, severity, status, assignee, ip, threat,
                        json.dumps([mitre["technique"]]), ts, ts, acked_at,
                        resolved_at, score, country, json.dumps(tags),
                    ),
                )
                aid = cur.lastrowid
                alert_map[fp] = aid

            conn.execute("UPDATE events SET alert_id = ? WHERE id = ?", (aid, event_id))

    # Campaigns — multi-port from top offenders + subnet burst
    camp_ips = [IPS[0][0], IPS[1][0], "203.0.113.50"]
    campaign_ids = []
    for i, cip in enumerate(camp_ips):
        first = (now - timedelta(hours=6 + i)).isoformat(timespec="seconds")
        last = (now - timedelta(minutes=10 + i)).isoformat(timespec="seconds")
        cur = conn.execute(
            """
            INSERT INTO campaigns
              (title, summary, severity, status, ips, ports, techniques,
               alert_count, first_seen, last_seen, risk_score)
            VALUES (?, ?, 'critical', 'active', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"Multi-vector recon from {cip}" if i < 2 else "Subnet burst 203.0.113.0/24",
                f"Observed SSH+HTTP(+FTP) activity from {cip}",
                json.dumps([cip] if i < 2 else ["203.0.113.50", "203.0.113.51", "203.0.113.52"]),
                json.dumps([2222, 8080, 2121] if i < 2 else [8080, 2222]),
                json.dumps(["T1110.001", "T1595.002"]),
                random.randint(4, 12),
                first, last, 85 + i,
            ),
        )
        cid = cur.lastrowid
        campaign_ids.append(cid)
        conn.execute(
            "UPDATE alerts SET campaign_id = ? WHERE ip = ? AND status NOT IN ('resolved','false_positive')",
            (cid, cip if i < 2 else "203.0.113.50"),
        )

    # Cases — one SLA-breached
    open_alerts = conn.execute(
        "SELECT id FROM alerts WHERE status IN ('new','acked','escalated') LIMIT 8"
    ).fetchall()
    alert_ids = [r[0] for r in open_alerts]

    cases = [
        (
            "Ongoing SSH brute from TOR exit",
            "critical",
            "open",
            "soc-lead",
            alert_ids[:3],
            campaign_ids[0] if campaign_ids else None,
            (now - timedelta(minutes=45)).isoformat(timespec="seconds"),  # breached
            (now - timedelta(hours=2)).isoformat(timespec="seconds"),
            json.dumps([
                {"author": "alice", "text": "Confirmed TOR exit node — escalating.", "at": (now - timedelta(hours=1)).isoformat(timespec="seconds")},
            ]),
            "",
        ),
        (
            "Web scanner cluster NL",
            "high",
            "open",
            "bob",
            alert_ids[3:5],
            campaign_ids[1] if len(campaign_ids) > 1 else None,
            (now + timedelta(minutes=40)).isoformat(timespec="seconds"),
            (now - timedelta(hours=1)).isoformat(timespec="seconds"),
            json.dumps([]),
            "",
        ),
        (
            "Closed: anonymous FTP probes",
            "medium",
            "closed",
            "alice",
            alert_ids[5:6],
            None,
            (now - timedelta(hours=5)).isoformat(timespec="seconds"),
            (now - timedelta(hours=8)).isoformat(timespec="seconds"),
            json.dumps([{"author": "alice", "text": "Contained and closed.", "at": (now - timedelta(hours=6)).isoformat(timespec="seconds")}]),
            "Benign research scanner — documented",
        ),
    ]

    for title, sev, status, assignee, aids, camp, sla, created, notes, reason in cases:
        closed = (now - timedelta(hours=5)).isoformat(timespec="seconds") if status == "closed" else None
        conn.execute(
            """
            INSERT INTO cases
              (title, severity, status, assignee, alert_ids, campaign_id,
               sla_due_at, created_at, closed_at, notes, close_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (title, sev, status, assignee, json.dumps(aids), camp, sla, created, closed, notes, reason),
        )

    # Blocklist samples
    for ip, reason, source, by, hours_ago in [
        (IPS[0][0], "auto-contain after 12 hits", "auto", "system", 3),
        (IPS[1][0], "recon burst playbook", "playbook", "bob", 1),
        ("45.142.212.100", "manual containment", "manual", "alice", 5),
    ]:
        blocked_at = (now - timedelta(hours=hours_ago)).isoformat(timespec="seconds")
        expires = (now + timedelta(hours=12 - hours_ago)).isoformat(timespec="seconds")
        conn.execute(
            """
            INSERT INTO blocklist (ip, reason, source, blocked_by, blocked_at, expires_at, active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (ip, reason, source, by, blocked_at, expires),
        )

    # Suppressions from FP
    conn.execute(
        """
        INSERT INTO suppression_rules
          (kind, value, reason, created_by, created_at, expires_at, active)
        VALUES ('threat_type', 'HTTP Probe', 'Noisy low-value probes', 'alice', ?, ?, 1)
        """,
        (
            (now - timedelta(hours=2)).isoformat(timespec="seconds"),
            (now + timedelta(hours=22)).isoformat(timespec="seconds"),
        ),
    )

    # Audit trail
    audit_actions = [
        ("system", "contain_ip", IPS[0][0], "auto: repeat offender"),
        ("alice", "ack_alert", "alert:1", "triage start"),
        ("bob", "run_playbook", "recon_burst_response", IPS[1][0]),
        ("alice", "false_positive", "alert:12", "suppress 24h"),
        ("soc-lead", "open_case", "case:1", "Ongoing SSH brute from TOR exit"),
        ("alice", "case_note", "case:1", "Confirmed TOR exit node"),
    ]
    for actor, action, target, detail in audit_actions:
        conn.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            ((now - timedelta(minutes=random.randint(5, 200))).isoformat(timespec="seconds"),
             actor, action, target, detail),
        )

    conn.commit()
    n_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    n_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    n_camps = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    conn.close()
    print(f"Seeded {event_count} events, {n_alerts} alerts, {n_camps} campaigns, {n_cases} cases")


if __name__ == "__main__":
    seed()
