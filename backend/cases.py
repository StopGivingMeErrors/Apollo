"""Case management helpers."""
from __future__ import annotations

import json
from datetime import timedelta

import database as db
from timeutil import utcnow, utcnow_iso


def _now() -> str:
    return utcnow_iso()


def open_case(
    *,
    title: str,
    severity: str,
    assignee: str,
    alert_ids: list[int] | None = None,
    campaign_id: int | None = None,
    sla_minutes: int = 60,
    actor: str = "system",
) -> dict:
    due = (utcnow() + timedelta(minutes=sla_minutes)).isoformat(timespec="seconds")
    case = db.create_case({
        "title": title,
        "severity": severity,
        "assignee": assignee,
        "alert_ids": json.dumps(alert_ids or []),
        "campaign_id": campaign_id,
        "sla_due_at": due,
        "created_at": _now(),
    })
    db.add_audit(actor, "open_case", f"case:{case['id']}", title)
    return case


def close_case(case_id: int, actor: str, reason: str = "") -> dict | None:
    updated = db.update_case(
        case_id,
        status="closed",
        closed_at=_now(),
        close_reason=reason,
    )
    if updated:
        db.add_audit(actor, "close_case", f"case:{case_id}", reason)
    return updated


def link_alert(case_id: int, alert_id: int, actor: str) -> dict | None:
    case = db.get_case(case_id)
    if not case:
        return None
    try:
        ids = json.loads(case.get("alert_ids") or "[]")
    except json.JSONDecodeError:
        ids = []
    if alert_id not in ids:
        ids.append(alert_id)
    updated = db.update_case(case_id, alert_ids=json.dumps(ids))
    db.add_audit(actor, "link_alert", f"case:{case_id}", f"alert:{alert_id}")
    return updated
