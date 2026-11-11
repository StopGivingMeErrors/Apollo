"""
Async TCP honeypot listeners.
Extracts attacker identity from X-Forwarded-For / src=IP when peer is localhost
(lab/demo mode) so GeoIP and threat maps work during local testing.
"""
import asyncio
import logging
import re
from typing import Callable, Awaitable

log = logging.getLogger("sentinel.honeypots")

EventCallback = Callable[[str, int, str, str, str], Awaitable[None]]

_IP_RE = re.compile(
    r"(?:X-Forwarded-For:\s*|src=)(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)


def resolve_source_ip(peer: str, payload: str) -> str:
    """Prefer spoofed/demo source when traffic is generated locally."""
    if peer not in ("127.0.0.1", "::1", "localhost"):
        return peer
    m = _IP_RE.search(payload or "")
    if m:
        return m.group(1)
    return peer


async def _accept(reader, writer, banner: bytes, timeout: float = 6.0) -> tuple[str, bytes]:
    peer = writer.get_extra_info("peername")[0]
    try:
        if banner:
            writer.write(banner)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except asyncio.TimeoutError:
        data = b""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return peer, data


async def _serve(host: str, port: int, handler) -> None:
    try:
        server = await asyncio.start_server(handler, host, port)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None) or str(exc)
        log.error(
            "Honeypot port %s unavailable (%s) — another Sentinel instance is likely still running. "
            "From backend run .\\start.ps1 (or: netstat -ano | findstr :%s then taskkill /PID <pid> /F).",
            port,
            code,
            port,
        )
        return
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("Honeypot listening on %s", addrs)
    async with server:
        await server.serve_forever()


async def ssh(port: int, on_event: EventCallback) -> None:
    async def handle(reader, writer):
        peer, data = await _accept(reader, writer, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        payload = data.decode(errors="ignore")
        ip = resolve_source_ip(peer, payload)
        severity = "critical" if len(payload) > 50 else ("high" if payload else "medium")
        threat = "SSH Brute Force" if payload else "SSH Probe"
        await on_event(ip, port, payload, threat, severity)
    await _serve("0.0.0.0", port, handle)


async def http(port: int, on_event: EventCallback) -> None:
    SQL = ["select", "union", "drop", "insert", "delete", "' --", "1=1", "or 1"]
    PATHS = ["/wp-login", "/phpmyadmin", "/.env", "/admin", "/shell", "/config", "/.git"]

    async def handle(reader, writer):
        peer, data = await _accept(reader, writer, b"", timeout=5.0)
        payload = data.decode(errors="ignore")
        if not payload:
            return
        ip = resolve_source_ip(peer, payload)
        lower = payload.lower()

        if any(k in lower for k in SQL):
            threat, severity = "SQL Injection", "critical"
        elif any(p in lower for p in PATHS):
            threat, severity = "Web Scanner", "high"
        elif "/../" in payload or "%2e%2e" in lower:
            threat, severity = "Path Traversal", "high"
        else:
            threat, severity = "HTTP Probe", "low"

        await on_event(ip, port, payload, threat, severity)
        try:
            writer.write(
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n"
                b"Content-Type: text/html\r\nContent-Length: 34\r\n\r\n"
                b"<html><body>Moved.</body></html>\r\n"
            )
            await writer.drain()
        except Exception:
            pass

    await _serve("0.0.0.0", port, handle)


async def ftp(port: int, on_event: EventCallback) -> None:
    async def handle(reader, writer):
        peer, data = await _accept(reader, writer, b"220 ProFTPD 1.3.7 Server (ProFTPD) ready\r\n")
        payload = data.decode(errors="ignore").strip()
        ip = resolve_source_ip(peer, payload)
        threat = "FTP Anonymous Access" if "anonymous" in payload.lower() else "FTP Auth Attempt"
        await on_event(ip, port, payload, threat, "medium")
        try:
            writer.write(b"530 Login incorrect.\r\n")
            await writer.drain()
        except Exception:
            pass

    await _serve("0.0.0.0", port, handle)


async def telnet(port: int, on_event: EventCallback) -> None:
    BANNER = b"\r\nDebian GNU/Linux 11\r\nlocalhost login: "

    async def handle(reader, writer):
        peer, data = await _accept(reader, writer, BANNER, timeout=8.0)
        payload = data.decode(errors="ignore")
        ip = resolve_source_ip(peer, payload)
        await on_event(ip, port, payload, "Telnet Login Attempt", "high")

    await _serve("0.0.0.0", port, handle)
