"""
Ambient live-attack simulator — feeds realistic geo-tagged probes through
the same SOC pipeline as honeypots so the dashboard always looks alive.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Awaitable, Callable

log = logging.getLogger("sentinel.live")

EventCallback = Callable[..., Awaitable[None]]

# Every event this module emits is tagged so the UI, API and database can
# always separate demo traffic from what the honeypots genuinely received.
SOURCE = "simulator"

# Real-looking attacker IPs with known GeoIP coverage in our seed/lookup table
ATTACKERS = [
    ("185.220.101.45", "TOR exit · Frankfurt"),
    ("194.165.16.72", "Russia · Moscow"),
    ("45.142.212.100", "Netherlands · Amsterdam"),
    ("103.21.244.12", "India · Mumbai"),
    ("191.96.249.55", "Brazil · São Paulo"),
    ("80.82.77.139", "Netherlands · scanner"),
    ("162.247.74.201", "USA · New York"),
    ("176.10.104.240", "Switzerland · Zurich"),
    ("51.15.43.205", "France · Paris"),
    ("109.201.133.195", "Netherlands · TOR"),
    ("221.194.47.242", "China · Beijing"),
    ("41.206.188.185", "Nigeria · Lagos"),
    ("91.219.237.88", "Ukraine · Kyiv"),
    ("5.188.206.123", "Russia · St Petersburg"),
    ("45.33.32.156", "USA · Fremont"),
    ("139.59.61.44", "Singapore"),
    ("34.102.136.180", "USA · cloud"),
    ("123.30.148.99", "Vietnam · Hanoi"),
]

SCENARIOS = [
    # (port, threat, severity, payload_fn)
    (2222, "SSH Brute Force", "high",
     lambda ip: f"SSH-2.0-OpenSSH_7.4\nroot:{random.choice(['admin','123456','toor'])} src={ip}"),
    (2222, "SSH Probe", "medium",
     lambda ip: f"SSH-2.0-libssh\nscan src={ip}"),
    (8080, "SQL Injection", "critical",
     lambda ip: f"GET /?id=1' UNION SELECT password FROM users-- HTTP/1.1\nX-Forwarded-For: {ip}"),
    (8080, "Web Scanner", "high",
     lambda ip: f"GET /wp-login.php HTTP/1.1\nX-Forwarded-For: {ip}"),
    (8080, "Path Traversal", "high",
     lambda ip: f"GET /../../etc/passwd HTTP/1.1\nX-Forwarded-For: {ip}"),
    (8080, "HTTP Probe", "low",
     lambda ip: f"GET /robots.txt HTTP/1.1\nX-Forwarded-For: {ip}"),
    (2121, "FTP Anonymous Access", "medium",
     lambda ip: f"USER anonymous src={ip}"),
    (2121, "FTP Auth Attempt", "medium",
     lambda ip: f"USER root PASS toor src={ip}"),
    (2323, "Telnet Login Attempt", "high",
     lambda ip: f"root\npassword\nsrc={ip}"),
]

# Scripted campaign bursts — multi-vector from one IP
CAMPAIGNS = [
    "194.165.16.72",
    "185.220.101.45",
    "45.142.212.100",
]

# Runtime gate. The generator task stays alive while paused so it can be
# resumed instantly; it simply parks on this event instead of emitting.
_running = asyncio.Event()
_running.set()


def is_running() -> bool:
    return _running.is_set()


def set_running(on: bool) -> bool:
    if on:
        _running.set()
        log.info("Attack simulator RESUMED")
    else:
        _running.clear()
        log.info("Attack simulator PAUSED — sensor traffic only")
    return _running.is_set()


async def run_live_attacks(on_event: EventCallback, interval: float = 1.8) -> None:
    """
    Continuously inject attacks. Mix of single probes + occasional multi-port bursts.
    """
    await asyncio.sleep(2.5)  # let honeypots / SSE clients settle
    log.info("Live attack simulator active — ambient global probes every ~%.1fs", interval)
    tick = 0
    while True:
        await _running.wait()
        try:
            tick += 1
            if tick % 14 == 0:
                # Multi-port campaign burst
                ip = random.choice(CAMPAIGNS)
                for port, threat, severity, payload_fn in random.sample(
                    [s for s in SCENARIOS if s[0] in (2222, 8080, 2121)], 3
                ):
                    await on_event(ip, port, payload_fn(ip), threat, severity, source=SOURCE)
                    await asyncio.sleep(0.15)
                log.info("Campaign burst ← %s (3 vectors)", ip)
            elif tick % 9 == 0:
                # Repeat-offender hammer (same IP, SSH)
                ip = "185.220.101.45"
                port, threat, severity, payload_fn = SCENARIOS[0]
                await on_event(ip, port, payload_fn(ip), threat, severity, source=SOURCE)
            else:
                ip, _note = random.choice(ATTACKERS)
                port, threat, severity, payload_fn = random.choice(SCENARIOS)
                await on_event(ip, port, payload_fn(ip), threat, severity, source=SOURCE)
        except Exception as exc:
            log.warning("live attack tick failed: %s", exc)
        # Jitter so it feels organic, not metronomic
        await asyncio.sleep(interval + random.uniform(-0.6, 0.9))
