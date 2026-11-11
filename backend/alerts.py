"""Alert triage transitions."""
from __future__ import annotations

import database as db
from timeutil import utcnow_iso


def _now() -> str:
    return utcnow_iso()


def acknowledge(alert_id: int, actor: str) -> dict | None:
    alert = db.get_alert(alert_id)
    if not alert:
        return None
    fields = {"status": "acked"}
    if not alert.get("acked_at"):
        fields["acked_at"] = _now()
    if not alert.get("assignee"):
        fields["assignee"] = actor
    updated = db.update_alert(alert_id, **fields)
    db.add_audit(actor, "ack_alert", f"alert:{alert_id}", alert.get("title", ""))
    return updated


def assign(alert_id: int, assignee: str, actor: str) -> dict | None:
    updated = db.update_alert(alert_id, assignee=assignee)
    if updated:
        db.add_audit(actor, "assign_alert", f"alert:{alert_id}", f"to {assignee}")
    return updated


def set_investigating(alert_id: int, actor: str) -> dict | None:
    alert = db.get_alert(alert_id)
    if not alert:
        return None
    fields = {"status": "investigating"}
    if not alert.get("acked_at"):
        fields["acked_at"] = _now()
    if not alert.get("assignee"):
        fields["assignee"] = actor
    updated = db.update_alert(alert_id, **fields)
    db.add_audit(actor, "investigate_alert", f"alert:{alert_id}", "")
    return updated


def escalate(alert_id: int, actor: str, assignee: str = "soc-lead") -> dict | None:
    alert = db.get_alert(alert_id)
    if not alert:
        return None
    fields = {"status": "escalated", "assignee": assignee, "severity": "critical"}
    if not alert.get("acked_at"):
        fields["acked_at"] = _now()
    updated = db.update_alert(alert_id, **fields)
    db.add_audit(actor, "escalate_alert", f"alert:{alert_id}", f"to {assignee}")
    return updated


def resolve(alert_id: int, actor: str, reason: str = "") -> dict | None:
    updated = db.update_alert(
        alert_id,
        status="resolved",
        resolved_at=_now(),
    )
    if updated:
        db.add_audit(actor, "resolve_alert", f"alert:{alert_id}", reason)
    return updated


def false_positive(alert_id: int, actor: str, suppress_hours: int = 24) -> dict | None:
    alert = db.get_alert(alert_id)
    if not alert:
        return None
    updated = db.update_alert(
        alert_id,
        status="false_positive",
        resolved_at=_now(),
    )
    db.add_suppression(
        "fingerprint",
        alert["fingerprint"],
        reason=f"FP on alert {alert_id}",
        created_by=actor,
        hours=suppress_hours,
    )
    db.add_audit(actor, "false_positive", f"alert:{alert_id}", f"suppress {suppress_hours}h")
    return updated
