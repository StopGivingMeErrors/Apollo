"""Enrichment — live GeoIP + live Tor exit intel (no curated demo lists)."""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from geoip import lookup as geo_lookup

log = logging.getLogger("sentinel.enrichment")

# Official Tor Project bulk exit list. Refreshed periodically; empty until first fetch.
_TOR_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_TTL_SEC = 6 * 60 * 60
_tor_exits: set[str] = set()
_tor_fetched_at = 0.0
_tor_lock = asyncio.Lock()
_tor_refresh_task: asyncio.Task | None = None


async def refresh_tor_exits(force: bool = False) -> int:
    """Pull the public Tor exit list. Returns number of exits loaded."""
    global _tor_exits, _tor_fetched_at
    now = time.time()
    if not force and _tor_exits and (now - _tor_fetched_at) < _TOR_TTL_SEC:
        return len(_tor_exits)

    async with _tor_lock:
        now = time.time()
        if not force and _tor_exits and (now - _tor_fetched_at) < _TOR_TTL_SEC:
            return len(_tor_exits)
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                r = await client.get(_TOR_URL)
                r.raise_for_status()
            exits = {
                line.strip()
                for line in r.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            _tor_exits = exits
            _tor_fetched_at = time.time()
            log.info("Tor exit list refreshed — %d exits", len(exits))
            return len(exits)
        except Exception as exc:
            log.warning("Tor exit list refresh failed: %s", exc)
            return len(_tor_exits)


async def _tor_refresh_loop() -> None:
    while True:
        await refresh_tor_exits(force=True)
        await asyncio.sleep(_TOR_TTL_SEC)


def start_intel_refresh() -> None:
    """Kick a background refresh so tags stay current without blocking ingest."""
    global _tor_refresh_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _tor_refresh_task and not _tor_refresh_task.done():
        return
    _tor_refresh_task = loop.create_task(_tor_refresh_loop())


def intel_tags_for(ip: str) -> list[str]:
    tags: list[str] = []
    if ip in _tor_exits:
        tags.append("tor")
    return tags


async def enrich(ip: str) -> dict:
    # Best-effort: if the list is still empty, try once without blocking forever.
    if not _tor_exits:
        try:
            await asyncio.wait_for(refresh_tor_exits(), timeout=3)
        except Exception:
            pass
    geo = await geo_lookup(ip)
    tags = intel_tags_for(ip)
    return {**geo, "intel_tags": tags}
