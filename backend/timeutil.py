"""
UTC time helpers.

`datetime.utcnow()` is deprecated and slated for removal. Every timestamp in
the schema is a naive UTC ISO-8601 string, and string comparison against those
values is used for SLA and expiry checks — so switching to aware datetimes
would silently change ordering. These helpers use the supported call and strip
the tzinfo, preserving the stored representation byte for byte.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_iso() -> str:
    return utcnow().isoformat(timespec="seconds")
