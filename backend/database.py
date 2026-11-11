"""SQLite persistence for Sentinel SOC v4."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any

from config import DB_PATH
from timeutil import utcnow, utcnow_iso

_local = threading.local()

ANALYSTS = [
    {"id": "alice", "name": "Alice Chen", "role": "Tier 1"},
    {"id": "bob", "name": "Bob Okonkwo", "role": "Tier 2"},
    {"id": "soc-lead", "name": "Sam Rivera", "role": "SOC Lead"},
]


def _conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        c = sqlite3.connect(DB_PATH, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return _local.conn


def _now() -> str:
    return utcnow_iso()


def _row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r else None


def _rows(rs) -> list[dict]:
    return [dict(r) for r in rs]


def _migrate_events(c: sqlite3.Connection) -> None:
    cols = {r[1] for r in c.execute("PRAGMA table_info(events)").fetchall()}
    alters = {
        "alert_id": "INTEGER",
        "mitre_technique": "TEXT DEFAULT ''",
        "risk_score": "INTEGER DEFAULT 0",
        "raw_hash": "TEXT DEFAULT ''",
        "intel_tags": "TEXT DEFAULT '[]'",
        # Rows written before provenance tracking existed cannot be attributed
        # to a sensor or the simulator, so they must not claim to be either.
        "source": "TEXT DEFAULT 'unlabelled'",
    }
    for col, typ in alters.items():
        if col not in cols:
            c.execute(f"ALTER TABLE events ADD COLUMN {col} {typ}")


def _migrate_alerts(c: sqlite3.Connection) -> None:
    cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
    if "source" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'unlabelled'")


def _migrate_blocklist(c: sqlite3.Connection) -> None:
    cols = {r[1] for r in c.execute("PRAGMA table_info(blocklist)").fetchall()}
    if "enforced" not in cols:
        c.execute("ALTER TABLE blocklist ADD COLUMN enforced INTEGER NOT NULL DEFAULT 0")


def init_db() -> None:
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            ip              TEXT    NOT NULL,
            port            INTEGER NOT NULL,
            payload         TEXT    DEFAULT '',
            threat_type     TEXT    NOT NULL,
            severity        TEXT    NOT NULL,
            country         TEXT    DEFAULT 'Unknown',
            city            TEXT    DEFAULT '',
            latitude        REAL,
            longitude       REAL,
            source          TEXT    NOT NULL DEFAULT 'sensor'
        );

        CREATE TABLE IF NOT EXISTS ip_counts (
            ip        TEXT PRIMARY KEY,
            hits      INTEGER NOT NULL DEFAULT 1,
            last_seen TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint       TEXT    NOT NULL,
            title             TEXT    NOT NULL,
            severity          TEXT    NOT NULL,
            status            TEXT    NOT NULL DEFAULT 'new',
            assignee          TEXT    DEFAULT '',
            ip                TEXT    NOT NULL,
            threat_type       TEXT    NOT NULL,
            mitre_techniques  TEXT    DEFAULT '[]',
            event_count       INTEGER NOT NULL DEFAULT 1,
            first_seen        TEXT    NOT NULL,
            last_seen         TEXT    NOT NULL,
            acked_at          TEXT,
            resolved_at       TEXT,
            risk_score        INTEGER DEFAULT 0,
            campaign_id       INTEGER,
            country           TEXT    DEFAULT 'Unknown',
            intel_tags        TEXT    DEFAULT '[]',
            source            TEXT    DEFAULT 'sensor'
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            summary     TEXT    DEFAULT '',
            severity    TEXT    NOT NULL DEFAULT 'high',
            status      TEXT    NOT NULL DEFAULT 'active',
            ips         TEXT    DEFAULT '[]',
            ports       TEXT    DEFAULT '[]',
            techniques  TEXT    DEFAULT '[]',
            alert_count INTEGER DEFAULT 0,
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL,
            risk_score  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS cases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'open',
            assignee    TEXT    DEFAULT '',
            alert_ids   TEXT    DEFAULT '[]',
            campaign_id INTEGER,
            sla_due_at  TEXT,
            created_at  TEXT    NOT NULL,
            closed_at   TEXT,
            notes       TEXT    DEFAULT '[]',
            close_reason TEXT   DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS blocklist (
            ip          TEXT PRIMARY KEY,
            reason      TEXT    DEFAULT '',
            source      TEXT    NOT NULL DEFAULT 'manual',
            blocked_by  TEXT    DEFAULT 'system',
            blocked_at  TEXT    NOT NULL,
            expires_at  TEXT,
            active      INTEGER NOT NULL DEFAULT 1,
            enforced    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            actor     TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            target    TEXT    DEFAULT '',
            detail    TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS suppression_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            kind        TEXT    NOT NULL,
            value       TEXT    NOT NULL,
            reason      TEXT    DEFAULT '',
            created_by  TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            active      INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS analysts (
            id   TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        );
    """)
    _migrate_events(c)
    _migrate_alerts(c)
    _migrate_blocklist(c)
    c.executescript("""
        CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip);
        CREATE INDEX IF NOT EXISTS idx_events_alert     ON events(alert_id);
        CREATE INDEX IF NOT EXISTS idx_ip_counts_hits   ON ip_counts(hits DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_fp        ON alerts(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_alerts_ip        ON alerts(ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_last      ON alerts(last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_cases_status     ON cases(status);
        CREATE INDEX IF NOT EXISTS idx_blocklist_active ON blocklist(active);
        CREATE INDEX IF NOT EXISTS idx_audit_ts         ON audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_supp_active      ON suppression_rules(active);
    """)
    for a in ANALYSTS:
        c.execute(
            "INSERT OR IGNORE INTO analysts (id, name, role) VALUES (:id, :name, :role)",
            a,
        )
    c.commit()


# ── Events ────────────────────────────────────────────────────────────────────

def insert_event(event: dict) -> int:
    c = _conn()
    cur = c.execute(
        """
        INSERT INTO events
          (timestamp, ip, port, payload, threat_type, severity, country, city,
           latitude, longitude, alert_id, mitre_technique, risk_score, raw_hash,
           intel_tags, source)
        VALUES
          (:timestamp, :ip, :port, :payload, :threat_type, :severity, :country, :city,
           :latitude, :longitude, :alert_id, :mitre_technique, :risk_score, :raw_hash,
           :intel_tags, :source)
        """,
        {
            **event,
            "alert_id": event.get("alert_id"),
            "mitre_technique": event.get("mitre_technique", ""),
            "risk_score": event.get("risk_score", 0),
            "raw_hash": event.get("raw_hash", ""),
            "intel_tags": event.get("intel_tags", "[]"),
            "source": event.get("source", "sensor"),
        },
    )
    c.execute(
        """
        INSERT INTO ip_counts (ip, hits, last_seen)
        VALUES (:ip, 1, :timestamp)
        ON CONFLICT(ip) DO UPDATE SET
            hits      = hits + 1,
            last_seen = excluded.last_seen
        """,
        event,
    )
    c.commit()
    return cur.lastrowid


def update_event_alert(event_id: int, alert_id: int) -> None:
    c = _conn()
    c.execute("UPDATE events SET alert_id = ? WHERE id = ?", (alert_id, event_id))
    c.commit()


def get_events(
    limit: int = 100,
    severity: str | None = None,
    ip: str | None = None,
    source: str | None = None,
) -> list[dict]:
    c = _conn()
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if ip:
        clauses.append("ip = ?")
        params.append(ip)
    if source:
        clauses.append("source = ?")
        params.append(source)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    return _rows(c.execute(
        f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?", params
    ).fetchall())


def get_ip_hits(ip: str) -> int:
    row = _conn().execute("SELECT hits FROM ip_counts WHERE ip = ?", (ip,)).fetchone()
    return row[0] if row else 0


def get_ports_for_ip(ip: str, since_hours: int = 1) -> list[int]:
    since = (utcnow() - timedelta(hours=since_hours)).isoformat(timespec="seconds")
    rows = _conn().execute(
        "SELECT DISTINCT port FROM events WHERE ip = ? AND timestamp >= ?",
        (ip, since),
    ).fetchall()
    return [r[0] for r in rows]


def get_ips_in_subnet24(ip: str, since_hours: int = 2) -> list[str]:
    parts = ip.split(".")
    if len(parts) != 4:
        return [ip]
    prefix = ".".join(parts[:3]) + "."
    since = (utcnow() - timedelta(hours=since_hours)).isoformat(timespec="seconds")
    rows = _conn().execute(
        "SELECT DISTINCT ip FROM events WHERE ip LIKE ? AND timestamp >= ?",
        (prefix + "%", since),
    ).fetchall()
    return [r[0] for r in rows]


# ── Alerts ────────────────────────────────────────────────────────────────────

def get_alert_by_fingerprint(fingerprint: str, open_only: bool = True) -> dict | None:
    c = _conn()
    if open_only:
        row = c.execute(
            """
            SELECT * FROM alerts
            WHERE fingerprint = ? AND status NOT IN ('resolved', 'false_positive')
            ORDER BY id DESC LIMIT 1
            """,
            (fingerprint,),
        ).fetchone()
    else:
        row = c.execute(
            "SELECT * FROM alerts WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
    return _row(row)


def create_alert(data: dict) -> dict:
    c = _conn()
    cur = c.execute(
        """
        INSERT INTO alerts
          (fingerprint, title, severity, status, assignee, ip, threat_type,
           mitre_techniques, event_count, first_seen, last_seen, risk_score,
           campaign_id, country, intel_tags, source)
        VALUES
          (:fingerprint, :title, :severity, :status, :assignee, :ip, :threat_type,
           :mitre_techniques, :event_count, :first_seen, :last_seen, :risk_score,
           :campaign_id, :country, :intel_tags, :source)
        """,
        {
            "status": "new",
            "assignee": "",
            "event_count": 1,
            "campaign_id": None,
            "intel_tags": "[]",
            "mitre_techniques": "[]",
            "source": "sensor",
            **data,
        },
    )
    c.commit()
    return get_alert(cur.lastrowid)


def bump_alert(alert_id: int, *, severity: str, risk_score: int, last_seen: str,
               mitre_techniques: str | None = None, intel_tags: str | None = None,
               source: str = "sensor") -> dict:
    c = _conn()
    alert = get_alert(alert_id)
    if not alert:
        raise ValueError("alert not found")
    sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    new_sev = severity if sev_rank.get(severity, 0) >= sev_rank.get(alert["severity"], 0) else alert["severity"]
    new_risk = max(risk_score, alert["risk_score"] or 0)
    # An alert fed by both real and simulated events must not claim to be either.
    prior = alert.get("source") or "sensor"
    new_source = prior if prior == source else "mixed"
    c.execute(
        """
        UPDATE alerts SET
          event_count = event_count + 1,
          last_seen = ?,
          severity = ?,
          risk_score = ?,
          mitre_techniques = COALESCE(?, mitre_techniques),
          intel_tags = COALESCE(?, intel_tags),
          source = ?
        WHERE id = ?
        """,
        (last_seen, new_sev, new_risk, mitre_techniques, intel_tags, new_source, alert_id),
    )
    c.commit()
    return get_alert(alert_id)


def get_alert(alert_id: int) -> dict | None:
    return _row(_conn().execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())


def list_alerts(
    limit: int = 100,
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    ip: str | None = None,
) -> list[dict]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if assignee:
        clauses.append("assignee = ?")
        params.append(assignee)
    if ip:
        clauses.append("ip = ?")
        params.append(ip)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    return _rows(_conn().execute(
        f"SELECT * FROM alerts {where} ORDER BY last_seen DESC LIMIT ?", params
    ).fetchall())


def update_alert(alert_id: int, **fields) -> dict | None:
    if not fields:
        return get_alert(alert_id)
    allowed = {
        "status", "assignee", "severity", "acked_at", "resolved_at",
        "campaign_id", "risk_score", "title",
    }
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return get_alert(alert_id)
    params.append(alert_id)
    c = _conn()
    c.execute(f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?", params)
    c.commit()
    return get_alert(alert_id)


def set_alert_campaign(alert_id: int, campaign_id: int) -> None:
    c = _conn()
    c.execute("UPDATE alerts SET campaign_id = ? WHERE id = ?", (campaign_id, alert_id))
    c.commit()


def open_alerts_for_ip(ip: str) -> list[dict]:
    return _rows(_conn().execute(
        """
        SELECT * FROM alerts
        WHERE ip = ? AND status NOT IN ('resolved', 'false_positive')
        ORDER BY last_seen DESC
        """,
        (ip,),
    ).fetchall())


# ── Campaigns ─────────────────────────────────────────────────────────────────

def create_campaign(data: dict) -> dict:
    c = _conn()
    cur = c.execute(
        """
        INSERT INTO campaigns
          (title, summary, severity, status, ips, ports, techniques,
           alert_count, first_seen, last_seen, risk_score)
        VALUES
          (:title, :summary, :severity, :status, :ips, :ports, :techniques,
           :alert_count, :first_seen, :last_seen, :risk_score)
        """,
        {
            "summary": "",
            "severity": "high",
            "status": "active",
            "ips": "[]",
            "ports": "[]",
            "techniques": "[]",
            "alert_count": 1,
            "risk_score": 50,
            **data,
        },
    )
    c.commit()
    return get_campaign(cur.lastrowid)


def get_campaign(campaign_id: int) -> dict | None:
    return _row(_conn().execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone())


def list_campaigns(limit: int = 50, status: str | None = None) -> list[dict]:
    if status:
        return _rows(_conn().execute(
            "SELECT * FROM campaigns WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
            (status, limit),
        ).fetchall())
    return _rows(_conn().execute(
        "SELECT * FROM campaigns ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall())


def update_campaign(campaign_id: int, **fields) -> dict | None:
    allowed = {
        "title", "summary", "severity", "status", "ips", "ports",
        "techniques", "alert_count", "last_seen", "risk_score",
    }
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return get_campaign(campaign_id)
    params.append(campaign_id)
    c = _conn()
    c.execute(f"UPDATE campaigns SET {', '.join(sets)} WHERE id = ?", params)
    c.commit()
    return get_campaign(campaign_id)


def find_active_campaign_for_ip(ip: str) -> dict | None:
    rows = list_campaigns(limit=100, status="active")
    for camp in rows:
        try:
            ips = json.loads(camp.get("ips") or "[]")
        except json.JSONDecodeError:
            ips = []
        if ip in ips:
            return camp
    return None


# ── Cases ─────────────────────────────────────────────────────────────────────

def create_case(data: dict) -> dict:
    c = _conn()
    cur = c.execute(
        """
        INSERT INTO cases
          (title, severity, status, assignee, alert_ids, campaign_id,
           sla_due_at, created_at, notes, close_reason)
        VALUES
          (:title, :severity, :status, :assignee, :alert_ids, :campaign_id,
           :sla_due_at, :created_at, :notes, :close_reason)
        """,
        {
            "status": "open",
            "assignee": "",
            "alert_ids": "[]",
            "campaign_id": None,
            "sla_due_at": None,
            "created_at": _now(),
            "notes": "[]",
            "close_reason": "",
            **data,
        },
    )
    c.commit()
    return get_case(cur.lastrowid)


def get_case(case_id: int) -> dict | None:
    return _row(_conn().execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())


def list_cases(limit: int = 50, status: str | None = None) -> list[dict]:
    if status:
        return _rows(_conn().execute(
            "SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall())
    return _rows(_conn().execute(
        "SELECT * FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall())


def update_case(case_id: int, **fields) -> dict | None:
    allowed = {
        "title", "severity", "status", "assignee", "alert_ids",
        "campaign_id", "sla_due_at", "closed_at", "notes", "close_reason",
    }
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return get_case(case_id)
    params.append(case_id)
    c = _conn()
    c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", params)
    c.commit()
    return get_case(case_id)


def add_case_note(case_id: int, author: str, text: str) -> dict | None:
    case = get_case(case_id)
    if not case:
        return None
    try:
        notes = json.loads(case.get("notes") or "[]")
    except json.JSONDecodeError:
        notes = []
    notes.append({"author": author, "text": text, "at": _now()})
    return update_case(case_id, notes=json.dumps(notes))


# ── Blocklist ─────────────────────────────────────────────────────────────────

def upsert_block(ip: str, reason: str, source: str, blocked_by: str,
                 expires_at: str | None = None, enforced: bool = False) -> dict:
    c = _conn()
    c.execute(
        """
        INSERT INTO blocklist
            (ip, reason, source, blocked_by, blocked_at, expires_at, active, enforced)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(ip) DO UPDATE SET
            reason = excluded.reason,
            source = excluded.source,
            blocked_by = excluded.blocked_by,
            blocked_at = excluded.blocked_at,
            expires_at = excluded.expires_at,
            active = 1,
            enforced = excluded.enforced
        """,
        (ip, reason, source, blocked_by, _now(), expires_at, 1 if enforced else 0),
    )
    c.commit()
    return get_block(ip)


def deactivate_block(ip: str) -> dict | None:
    c = _conn()
    c.execute("UPDATE blocklist SET active = 0 WHERE ip = ?", (ip,))
    c.commit()
    return get_block(ip)


def get_block(ip: str) -> dict | None:
    return _row(_conn().execute("SELECT * FROM blocklist WHERE ip = ?", (ip,)).fetchone())


def list_blocks(active_only: bool = True) -> list[dict]:
    if active_only:
        return _rows(_conn().execute(
            "SELECT * FROM blocklist WHERE active = 1 ORDER BY blocked_at DESC"
        ).fetchall())
    return _rows(_conn().execute(
        "SELECT * FROM blocklist ORDER BY blocked_at DESC"
    ).fetchall())


def active_block_count() -> int:
    return _conn().execute("SELECT COUNT(*) FROM blocklist WHERE active = 1").fetchone()[0]


def enforced_block_count() -> int:
    return _conn().execute(
        "SELECT COUNT(*) FROM blocklist WHERE active = 1 AND enforced = 1"
    ).fetchone()[0]


def expired_active_blocks() -> list[dict]:
    now = _now()
    return _rows(_conn().execute(
        """
        SELECT * FROM blocklist
        WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?
        """,
        (now,),
    ).fetchall())


# ── Audit / suppressions / analysts ───────────────────────────────────────────

def add_audit(actor: str, action: str, target: str = "", detail: str = "") -> dict:
    c = _conn()
    cur = c.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
        (_now(), actor, action, target, detail),
    )
    c.commit()
    return _row(c.execute("SELECT * FROM audit_log WHERE id = ?", (cur.lastrowid,)).fetchone())


def list_audit(limit: int = 100) -> list[dict]:
    return _rows(_conn().execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall())


def add_suppression(kind: str, value: str, reason: str, created_by: str,
                    hours: int = 24) -> dict:
    expires = (utcnow() + timedelta(hours=hours)).isoformat(timespec="seconds")
    c = _conn()
    cur = c.execute(
        """
        INSERT INTO suppression_rules
          (kind, value, reason, created_by, created_at, expires_at, active)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        (kind, value, reason, created_by, _now(), expires),
    )
    c.commit()
    return _row(c.execute(
        "SELECT * FROM suppression_rules WHERE id = ?", (cur.lastrowid,)
    ).fetchone())


def is_suppressed(fingerprint: str, ip: str, threat_type: str) -> dict | None:
    now = _now()
    c = _conn()
    c.execute(
        "UPDATE suppression_rules SET active = 0 WHERE active = 1 AND expires_at <= ?",
        (now,),
    )
    c.commit()
    row = c.execute(
        """
        SELECT * FROM suppression_rules
        WHERE active = 1 AND expires_at > ? AND (
            (kind = 'fingerprint' AND value = ?) OR
            (kind = 'ip' AND value = ?) OR
            (kind = 'threat_type' AND value = ?)
        )
        LIMIT 1
        """,
        (now, fingerprint, ip, threat_type),
    ).fetchone()
    return _row(row)


def list_analysts() -> list[dict]:
    return _rows(_conn().execute("SELECT * FROM analysts ORDER BY id").fetchall())


# ── Stats / metrics / investigate ─────────────────────────────────────────────

def count_events() -> int:
    return _conn().execute("SELECT COUNT(*) FROM events").fetchone()[0]


def get_stats() -> dict:
    c = _conn()
    total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked = active_block_count()
    scanners = c.execute("SELECT COUNT(*) FROM ip_counts").fetchone()[0]
    critical = c.execute("SELECT COUNT(*) FROM events WHERE severity='critical'").fetchone()[0]
    open_alerts = c.execute(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acked','investigating','escalated')"
    ).fetchone()[0]
    active_campaigns = c.execute(
        "SELECT COUNT(*) FROM campaigns WHERE status='active'"
    ).fetchone()[0]
    open_cases = c.execute(
        "SELECT COUNT(*) FROM cases WHERE status='open'"
    ).fetchone()[0]
    breached_slas = c.execute(
        """
        SELECT COUNT(*) FROM cases
        WHERE status='open' AND sla_due_at IS NOT NULL AND sla_due_at < ?
        """,
        (_now(),),
    ).fetchone()[0]

    severity_rows = c.execute(
        "SELECT severity, COUNT(*) FROM events GROUP BY severity"
    ).fetchall()
    threat_rows = c.execute(
        """
        SELECT threat_type, COUNT(*) AS cnt FROM events
        GROUP BY threat_type ORDER BY cnt DESC LIMIT 6
        """
    ).fetchall()
    geo_rows = c.execute(
        """
        SELECT country, COUNT(*) AS cnt FROM events
        WHERE country NOT IN ('Unknown', 'Private', '')
        GROUP BY country ORDER BY cnt DESC LIMIT 8
        """
    ).fetchall()
    history_rows = c.execute(
        """
        SELECT strftime('%H:00', timestamp) AS hour, COUNT(*) AS cnt
        FROM events WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour ORDER BY hour ASC
        """
    ).fetchall()
    top_ips = c.execute(
        "SELECT ip, hits, last_seen FROM ip_counts ORDER BY hits DESC LIMIT 8"
    ).fetchall()
    mitre_rows = c.execute(
        """
        SELECT mitre_technique, COUNT(*) AS cnt FROM events
        WHERE mitre_technique != '' AND mitre_technique IS NOT NULL
        GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 10
        """
    ).fetchall()
    alert_status = c.execute(
        "SELECT status, COUNT(*) FROM alerts GROUP BY status"
    ).fetchall()
    source_rows = c.execute(
        "SELECT COALESCE(source, 'sensor'), COUNT(*) FROM events GROUP BY 1"
    ).fetchall()
    source_breakdown = dict(source_rows)

    return {
        "total_events": total,
        "source_breakdown": source_breakdown,
        "simulated_events": source_breakdown.get("simulator", 0),
        "sensor_events": source_breakdown.get("sensor", 0),
        "blocked": blocked,
        "blocks_enforced": enforced_block_count(),
        "active_scanners": scanners,
        "critical": critical,
        "open_alerts": open_alerts,
        "active_campaigns": active_campaigns,
        "open_cases": open_cases,
        "breached_slas": breached_slas,
        "severity_breakdown": dict(severity_rows),
        "alert_status_breakdown": dict(alert_status),
        "top_threats": [list(r) for r in threat_rows],
        "geo_breakdown": [list(r) for r in geo_rows],
        "hourly_history": [list(r) for r in history_rows],
        "top_ips": [dict(r) for r in top_ips],
        "mitre_heatmap": [list(r) for r in mitre_rows],
    }


def get_geo_points(limit: int = 80) -> list[dict]:
    """Aggregate recent events into map points (lat/lon required)."""
    c = _conn()
    rows = c.execute(
        """
        SELECT ip, country, city,
               AVG(latitude) AS latitude,
               AVG(longitude) AS longitude,
               COUNT(*) AS hits,
               MAX(severity) AS severity,
               MAX(timestamp) AS last_seen,
               MAX(threat_type) AS threat_type,
               MAX(risk_score) AS risk_score
        FROM events
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
          AND country NOT IN ('Private', 'Unknown', '')
        GROUP BY ip
        ORDER BY hits DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_metrics() -> dict:
    c = _conn()
    # MTTA: avg seconds from first_seen to acked_at
    mtta_rows = c.execute(
        """
        SELECT first_seen, acked_at FROM alerts
        WHERE acked_at IS NOT NULL
        """
    ).fetchall()
    mttr_rows = c.execute(
        """
        SELECT first_seen, resolved_at FROM alerts
        WHERE resolved_at IS NOT NULL
        """
    ).fetchall()

    def _avg_delta(rows) -> float | None:
        deltas = []
        for a, b in rows:
            try:
                t0 = datetime.fromisoformat(a)
                t1 = datetime.fromisoformat(b)
                deltas.append((t1 - t0).total_seconds())
            except Exception:
                continue
        return round(sum(deltas) / len(deltas), 1) if deltas else None

    total_alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    fp = c.execute(
        "SELECT COUNT(*) FROM alerts WHERE status='false_positive'"
    ).fetchone()[0]
    resolved = c.execute(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('resolved','false_positive')"
    ).fetchone()[0]
    open_q = c.execute(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acked','investigating','escalated')"
    ).fetchone()[0]
    auto_blocks = c.execute(
        "SELECT COUNT(*) FROM blocklist WHERE source='auto' OR source='playbook'"
    ).fetchone()[0]
    manual_blocks = c.execute(
        "SELECT COUNT(*) FROM blocklist WHERE source='manual'"
    ).fetchone()[0]

    by_day = c.execute(
        """
        SELECT date(first_seen) AS d,
               COUNT(*) AS opened,
               SUM(CASE WHEN status IN ('resolved','false_positive') THEN 1 ELSE 0 END) AS closed
        FROM alerts
        WHERE first_seen >= datetime('now', '-7 days')
        GROUP BY d ORDER BY d ASC
        """
    ).fetchall()

    return {
        "mtta_seconds": _avg_delta(mtta_rows),
        "mttr_seconds": _avg_delta(mttr_rows),
        "open_queue": open_q,
        "total_alerts": total_alerts,
        "resolved": resolved,
        "fp_count": fp,
        "fp_rate": round(fp / total_alerts, 3) if total_alerts else 0,
        "auto_containments": auto_blocks,
        "manual_containments": manual_blocks,
        "volume_by_day": [dict(r) for r in by_day],
        "active_blocks": active_block_count(),
    }


def investigate_ip(ip: str) -> dict:
    events = get_events(limit=200, ip=ip)
    alerts = list_alerts(limit=50, ip=ip)
    block = get_block(ip)
    hits = get_ip_hits(ip)
    ports = get_ports_for_ip(ip, since_hours=24)
    campaign = find_active_campaign_for_ip(ip)
    risk = 0
    if alerts:
        risk = max((a.get("risk_score") or 0) for a in alerts)
    elif events:
        risk = max((e.get("risk_score") or 0) for e in events)
    geo = {}
    if events:
        geo = {
            "country": events[0].get("country"),
            "city": events[0].get("city"),
            "latitude": events[0].get("latitude"),
            "longitude": events[0].get("longitude"),
        }
    return {
        "ip": ip,
        "hits": hits,
        "risk_score": risk,
        "ports": ports,
        "geo": geo,
        "block": block,
        "campaign": campaign,
        "events": events,
        "alerts": alerts,
    }
