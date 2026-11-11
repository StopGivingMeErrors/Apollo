"""Alert fingerprinting and campaign correlation."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

import database as db
from detection import mitre_for
from timeutil import utcnow


def fingerprint(ip: str, threat_type: str, ts: str | None = None) -> str:
    """Dedup key: ip + threat + hour bucket → 200 probes become 1 alert."""
    if ts:
        try:
            hour = datetime.fromisoformat(ts).strftime("%Y%m%d%H")
        except ValueError:
            hour = utcnow().strftime("%Y%m%d%H")
    else:
        hour = utcnow().strftime("%Y%m%d%H")
    raw = f"{ip}|{threat_type}|{hour}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def raw_hash(ip: str, port: int, payload: str, threat: str) -> str:
    raw = f"{ip}|{port}|{threat}|{payload[:120]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _merge_json_list(existing: str | None, additions: list) -> str:
    try:
        cur = json.loads(existing or "[]")
    except json.JSONDecodeError:
        cur = []
    for a in additions:
        if a not in cur:
            cur.append(a)
    return json.dumps(cur)


def correlate_campaign(ip: str, port: int, threat_type: str, severity: str,
                       technique: str, risk: int, ts: str) -> dict | None:
    """
    Open or update a campaign when:
    - same IP hits ≥2 distinct ports in the last hour, OR
    - ≥3 distinct IPs in the same /24 are active in the last 2 hours
    """
    ports = db.get_ports_for_ip(ip, since_hours=1)
    if port not in ports:
        ports = list(ports) + [port]

    subnet_ips = db.get_ips_in_subnet24(ip, since_hours=2)
    if ip not in subnet_ips:
        subnet_ips = list(subnet_ips) + [ip]

    multi_port = len(set(ports)) >= 2
    subnet_burst = len(set(subnet_ips)) >= 3

    if not multi_port and not subnet_burst:
        return None

    existing = db.find_active_campaign_for_ip(ip)
    mitre = mitre_for(threat_type)
    tech = technique or mitre["technique"]

    if existing:
        ips = _merge_json_list(existing.get("ips"), [ip])
        ports_j = _merge_json_list(existing.get("ports"), [port])
        techs = _merge_json_list(existing.get("techniques"), [tech])
        sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        new_sev = severity if sev_rank.get(severity, 0) >= sev_rank.get(existing["severity"], 0) else existing["severity"]
        return db.update_campaign(
            existing["id"],
            ips=ips,
            ports=ports_j,
            techniques=techs,
            alert_count=(existing.get("alert_count") or 0) + 1,
            last_seen=ts,
            severity=new_sev,
            risk_score=max(risk, existing.get("risk_score") or 0),
            summary=_campaign_summary(json.loads(ips), json.loads(ports_j), multi_port, subnet_burst),
        )

    title = (
        f"Multi-vector recon from {ip}"
        if multi_port
        else f"Subnet burst {'.'.join(ip.split('.')[:3])}.0/24"
    )
    return db.create_campaign({
        "title": title,
        "summary": _campaign_summary([ip], list(set(ports)), multi_port, subnet_burst),
        "severity": "critical" if severity == "critical" else "high",
        "ips": json.dumps([ip]),
        "ports": json.dumps(sorted(set(ports))),
        "techniques": json.dumps([tech]),
        "alert_count": 1,
        "first_seen": ts,
        "last_seen": ts,
        "risk_score": max(risk, 70),
    })


def _campaign_summary(ips: list, ports: list, multi_port: bool, subnet_burst: bool) -> str:
    parts = []
    if multi_port:
        parts.append(f"Multi-port sweep across {sorted(set(ports))}")
    if subnet_burst:
        parts.append(f"Coordinated activity from {len(set(ips))} hosts in /24")
    parts.append(f"Primary actor {ips[0] if ips else 'unknown'}")
    return ". ".join(parts)
