"""High-level containment actions with persistence and audit."""
from __future__ import annotations

from datetime import timedelta

import blocker
import database as db
from timeutil import utcnow


def contain_ip(
    ip: str,
    *,
    reason: str,
    source: str,
    actor: str,
    hours: int | None = None,
) -> dict:
    if ip in blocker.WHITELIST:
        return {"ok": False, "error": "whitelisted", "ip": ip}
    if not blocker.is_valid_ip(ip):
        return {"ok": False, "error": "invalid IP address", "ip": ip}

    expires_at = None
    if hours:
        expires_at = (utcnow() + timedelta(hours=hours)).isoformat(timespec="seconds")

    fw = blocker.block_ip(ip)
    row = db.upsert_block(
        ip, reason, source, actor, expires_at, enforced=fw["enforced"]
    )
    detail = f"{source}: {reason}"
    if not fw["enforced"]:
        detail += f" [NOT ENFORCED: {fw['error']}]"
    audit = db.add_audit(actor, "contain_ip", ip, detail)
    return {
        "ok": True,
        "enforced": fw["enforced"],
        "firewall_error": fw["error"],
        "block": row,
        "audit": audit,
    }


def release_ip(ip: str, *, actor: str, reason: str = "manual release") -> dict:
    fw = blocker.unblock_ip(ip)
    row = db.deactivate_block(ip)
    audit = db.add_audit(actor, "release_ip", ip, reason)
    return {
        "ok": True,
        "enforced": fw["enforced"],
        "firewall_error": fw["error"],
        "block": row,
        "audit": audit,
    }


def sweep_expired(*, actor: str = "system") -> list[dict]:
    released = []
    for row in db.expired_active_blocks():
        result = release_ip(row["ip"], actor=actor, reason="expiry")
        released.append(result)
    return released
