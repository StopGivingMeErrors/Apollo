"""Central event pipeline — enrich, score, fingerprint, correlate, respond."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Any

import config
import database as db
import playbooks
from blocker import WHITELIST
from correlation import correlate_campaign, fingerprint, raw_hash
from detection import alert_title, mitre_for, risk_score
from enrichment import enrich
from timeutil import utcnow_iso

log = logging.getLogger("sentinel.pipeline")

_broadcast: deque[dict] = deque(maxlen=500)
_seq = 0
_subscribers: set[asyncio.Queue] = set()


def get_broadcast() -> deque:
    return _broadcast


def subscribe() -> asyncio.Queue:
    """Per-client push queue — instant SSE delivery."""
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def publish(msg_type: str, data: dict) -> None:
    global _seq
    _seq += 1
    envelope = {"type": msg_type, "data": data, "seq": _seq}
    _broadcast.appendleft(envelope)
    dead = []
    for q in _subscribers:
        try:
            q.put_nowait(envelope)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
                q.put_nowait(envelope)
            except Exception:
                dead.append(q)
        except Exception:
            dead.append(q)
    for q in dead:
        _subscribers.discard(q)


def _now() -> str:
    return utcnow_iso()


async def on_event(
    ip: str,
    port: int,
    payload: str,
    threat: str,
    severity: str,
    source: str = "sensor",
) -> None:
    """
    Honeypot callback — full SOC pipeline.

    `source` records how the observation arrived: "sensor" for traffic a
    honeypot actually received, "simulator" for ambient demo traffic. It is
    persisted on every event and alert so the two are never conflated.
    """
    ts = _now()
    geo = await enrich(ip)
    hits = db.get_ip_hits(ip)
    ports = db.get_ports_for_ip(ip, since_hours=1)
    port_count = len(set(ports) | {port})
    tags = geo.get("intel_tags") or []

    if hits + 1 >= config.REPEAT_ESCALATE_HITS and severity != "critical":
        severity = "critical"
    elif hits + 1 >= config.REPEAT_MEDIUM_MIN_HITS and severity == "low":
        severity = "medium"

    mitre = mitre_for(threat)
    score = risk_score(
        severity=severity,
        hits=hits + 1,
        port_count=port_count,
        intel_tags=tags,
        country=geo.get("country", ""),
    )
    fp = fingerprint(ip, threat, ts)
    suppressed = db.is_suppressed(fp, ip, threat)

    event = {
        "timestamp": ts,
        "ip": ip,
        "port": port,
        "payload": (payload or "")[:300],
        "threat_type": threat,
        "severity": severity,
        "country": geo.get("country", "Unknown"),
        "city": geo.get("city", ""),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "alert_id": None,
        "mitre_technique": mitre["technique"],
        "risk_score": score,
        "raw_hash": raw_hash(ip, port, payload or "", threat),
        "intel_tags": json.dumps(tags),
        "source": source,
        "repeat_offender": hits + 1 >= config.REPEAT_MEDIUM_MIN_HITS,
    }

    event_id = db.insert_event(event)
    event["id"] = event_id

    alert: dict[str, Any] | None = None
    if suppressed:
        existing = db.get_alert_by_fingerprint(fp, open_only=False)
        if existing and existing["status"] not in ("resolved", "false_positive"):
            alert = db.update_alert(
                existing["id"],
                status="false_positive",
                resolved_at=ts,
            )
        event["suppressed"] = True
        publish("event", event)
        log.info("[SUPPRESS] %s %s — %s", threat, ip, suppressed.get("reason"))
        return

    existing = db.get_alert_by_fingerprint(fp, open_only=True)
    techniques_json = json.dumps([mitre["technique"]])
    tags_json = json.dumps(tags)

    if existing:
        alert = db.bump_alert(
            existing["id"],
            severity=severity,
            risk_score=score,
            last_seen=ts,
            mitre_techniques=techniques_json,
            intel_tags=tags_json,
            source=source,
        )
        alert["title"] = alert_title(threat, ip, alert["event_count"])
        db.update_alert(alert["id"], title=alert["title"])
        alert = db.get_alert(alert["id"])
    else:
        alert = db.create_alert({
            "fingerprint": fp,
            "title": alert_title(threat, ip, 1),
            "severity": severity,
            "ip": ip,
            "threat_type": threat,
            "mitre_techniques": techniques_json,
            "event_count": 1,
            "first_seen": ts,
            "last_seen": ts,
            "risk_score": score,
            "country": geo.get("country", "Unknown"),
            "intel_tags": tags_json,
            "source": source,
        })

    db.update_event_alert(event_id, alert["id"])
    event["alert_id"] = alert["id"]

    campaign = correlate_campaign(
        ip, port, threat, severity, mitre["technique"], score, ts
    )
    if campaign:
        db.set_alert_campaign(alert["id"], campaign["id"])
        alert = db.get_alert(alert["id"])

    # Alert first so triage UI never misses the frame
    publish("alert", alert)
    publish("event", event)
    if campaign:
        publish("campaign", campaign)
    # Lightweight stats pulse so UI KPIs move in realtime
    publish("stats_hint", {"open_alerts": True, "ip": ip, "severity": severity})

    if hits + 1 >= config.REPEAT_ESCALATE_HITS and ip not in WHITELIST:
        result = playbooks.run_playbook(
            "auto_contain_repeat_offender",
            {"ip": ip, "hits": hits + 1},
            actor="system",
        )
        if result.get("ok"):
            publish("action", {"action": "auto_contain", "ip": ip, "result": result})

    if campaign and campaign.get("alert_count", 0) <= 2 and len(json.loads(campaign.get("ports") or "[]")) >= 2:
        publish("action", {
            "action": "campaign_detected",
            "campaign_id": campaign["id"],
            "ip": ip,
        })

    log.info(
        "[%s] %s %s — %s (%s/%s) · risk=%s · alert=#%s · hits=%s",
        severity.upper().ljust(8),
        "SIM " if source == "simulator" else "REAL",
        threat.ljust(22),
        ip,
        geo.get("country"),
        geo.get("city") or "—",
        score,
        alert["id"],
        hits + 1,
    )
