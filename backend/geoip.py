"""
GeoIP resolver — live lookup via ip-api.com (cached in-process).
Private/loopback addresses stay local; there is no curated attacker atlas.
"""
from __future__ import annotations

import ipaddress
import httpx
import logging

log = logging.getLogger("sentinel.geoip")

_cache: dict[str, dict] = {}

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
    )
]

_EMPTY = {"country": "Unknown", "city": "", "latitude": None, "longitude": None}
_PRIVATE = {"country": "Private", "city": "Lab", "latitude": None, "longitude": None}

# Empty on purpose — live lookups never use a curated atlas.
# seed_data.py may still import these names for offline demo seeding.
ATTACKER_ATLAS: dict[str, dict] = {}
COUNTRY_CENTROID: dict[str, tuple[float, float]] = {}


def _is_loopback_only(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback
    except ValueError:
        return False


def _is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS) and not addr.is_loopback
    except ValueError:
        return False


async def lookup(ip: str) -> dict:
    if _is_loopback_only(ip):
        return _PRIVATE

    if ip in _cache:
        return _cache[ip]

    if _is_rfc1918(ip):
        return _PRIVATE

    try:
        async with httpx.AsyncClient(timeout=4) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,lat,lon"},
            )
            r.raise_for_status()
            d = r.json()
            if d.get("status") == "success":
                result = {
                    "country": d.get("country", "Unknown"),
                    "city": d.get("city", ""),
                    "latitude": d.get("lat"),
                    "longitude": d.get("lon"),
                }
                _cache[ip] = result
                return result
    except Exception as exc:
        log.debug("GeoIP lookup failed for %s: %s", ip, exc)

    return _EMPTY


def coords_for_country(country: str) -> tuple[float | None, float | None]:
    return COUNTRY_CENTROID.get(country, (None, None))
