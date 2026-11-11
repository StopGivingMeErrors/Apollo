"""SOAR-style playbooks — declarative response automation."""
from __future__ import annotations

import json
from typing import Any

import actions
import alerts as alert_svc
import cases as case_svc
import database as db

PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "contain_ip",
        "name": "Contain IP",
        "description": "Block the source IP at the firewall and annotate audit log.",
        "params": ["ip", "reason"],
    },
    {
        "id": "escalate_critical",
        "name": "Escalate Critical",
        "description": "Escalate alert, open a case assigned to SOC Lead with 30m SLA.",
        "params": ["alert_id"],
    },
    {
        "id": "recon_burst_response",
        "name": "Recon Burst Response",
        "description": "For multi-port campaigns: contain IP, open case, escalate linked alerts.",
        "params": ["ip", "campaign_id"],
    },
    {
        "id": "false_positive_cleanup",
        "name": "False Positive Cleanup",
        "description": "Mark alert FP and suppress fingerprint for 24h.",
        "params": ["alert_id"],
    },
    {
        "id": "auto_contain_repeat_offender",
        "name": "Auto-Contain Repeat Offender",
        "description": "System playbook: contain IP after repeat threshold.",
        "params": ["ip", "hits"],
        "system": True,
    },
]


def list_playbooks(include_system: bool = False) -> list[dict]:
    if include_system:
        return PLAYBOOKS
    return [p for p in PLAYBOOKS if not p.get("system")]


def run_playbook(playbook_id: str, params: dict, actor: str = "system") -> dict:
    runners = {
        "contain_ip": _contain_ip,
        "escalate_critical": _escalate_critical,
        "recon_burst_response": _recon_burst,
        "false_positive_cleanup": _fp_cleanup,
        "auto_contain_repeat_offender": _auto_contain,
    }
    fn = runners.get(playbook_id)
    if not fn:
        return {"ok": False, "error": f"unknown playbook {playbook_id}"}
    result = fn(params, actor)
    db.add_audit(actor, "run_playbook", playbook_id, json.dumps(params)[:300])
    return result


def _contain_ip(params: dict, actor: str) -> dict:
    ip = params.get("ip")
    if not ip:
        return {"ok": False, "error": "ip required"}
    return actions.contain_ip(
        ip,
        reason=params.get("reason", "playbook contain_ip"),
        source="playbook",
        actor=actor,
        hours=params.get("hours"),
    )


def _escalate_critical(params: dict, actor: str) -> dict:
    alert_id = params.get("alert_id")
    if not alert_id:
        return {"ok": False, "error": "alert_id required"}
    alert = alert_svc.escalate(int(alert_id), actor, assignee="soc-lead")
    if not alert:
        return {"ok": False, "error": "alert not found"}
    case = case_svc.open_case(
        title=f"Escalation: {alert['title']}",
        severity="critical",
        assignee="soc-lead",
        alert_ids=[alert["id"]],
        campaign_id=alert.get("campaign_id"),
        sla_minutes=30,
        actor=actor,
    )
    return {"ok": True, "alert": alert, "case": case}


def _recon_burst(params: dict, actor: str) -> dict:
    ip = params.get("ip")
    if not ip:
        return {"ok": False, "error": "ip required"}
    contain = actions.contain_ip(
        ip,
        reason="recon burst / multi-vector campaign",
        source="playbook",
        actor=actor,
        hours=24,
    )
    open_alerts = db.open_alerts_for_ip(ip)
    for a in open_alerts:
        alert_svc.escalate(a["id"], actor)
    case = case_svc.open_case(
        title=f"Recon burst response — {ip}",
        severity="critical",
        assignee="soc-lead",
        alert_ids=[a["id"] for a in open_alerts],
        campaign_id=params.get("campaign_id"),
        sla_minutes=30,
        actor=actor,
    )
    return {"ok": True, "contain": contain, "case": case, "escalated": len(open_alerts)}


def _fp_cleanup(params: dict, actor: str) -> dict:
    alert_id = params.get("alert_id")
    if not alert_id:
        return {"ok": False, "error": "alert_id required"}
    alert = alert_svc.false_positive(int(alert_id), actor, suppress_hours=24)
    if not alert:
        return {"ok": False, "error": "alert not found"}
    return {"ok": True, "alert": alert}


def _auto_contain(params: dict, actor: str) -> dict:
    ip = params.get("ip")
    hits = params.get("hits", 0)
    return actions.contain_ip(
        ip,
        reason=f"auto-contain after {hits} hits",
        source="auto",
        actor=actor or "system",
        hours=12,
    )
