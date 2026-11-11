"""
OS firewall containment.

Enforcement can legitimately fail — no admin rights, no iptables, containerised
host. When it does we still record the intent so the blocklist stays coherent,
but we never report it as enforced. Callers must surface the difference:
an analyst who believes a live attacker is contained when it isn't is worse off
than one who knows the block failed.
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess

log = logging.getLogger("sentinel.blocker")

# IPs we intend to block, and the subset the OS firewall actually enforces.
_intended: set[str] = set()
_enforced: set[str] = set()
WHITELIST = {"127.0.0.1", "::1", "localhost"}

_ENFORCEMENT_PROBE: bool | None = None


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_blocked(ip: str) -> bool:
    return ip in _intended


def is_enforced(ip: str) -> bool:
    return ip in _enforced


def list_memory_blocks() -> list[str]:
    return sorted(_intended)


def _rule_name(ip: str) -> str:
    return f"SENTINEL_BLOCK_{ip}"


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(args, check=False, capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"").decode(errors="ignore").strip()
        return False, detail or f"exit {proc.returncode}"
    return True, ""


def _add_rule(ip: str) -> tuple[bool, str]:
    if platform.system() == "Windows":
        return _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_rule_name(ip)}",
            "dir=in", "action=block", f"remoteip={ip}", "protocol=any",
        ])
    return _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])


def _delete_rule(ip: str) -> tuple[bool, str]:
    if platform.system() == "Windows":
        return _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_rule_name(ip)}",
        ])
    return _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


def _probe_enforcement() -> bool:
    """
    Querying the firewall succeeds without elevation, so a read tells us
    nothing. Write a throwaway rule for a TEST-NET-3 address (RFC 5737, never
    routed) and remove it again — that is the only honest check.
    """
    probe_ip = "203.0.113.255"
    ok, _ = _add_rule(probe_ip)
    if ok:
        _delete_rule(probe_ip)
    return ok


def enforcement_status() -> dict:
    """Report whether this process can actually program the OS firewall."""
    global _ENFORCEMENT_PROBE
    if _ENFORCEMENT_PROBE is None:
        _ENFORCEMENT_PROBE = _probe_enforcement()
    return {
        "available": _ENFORCEMENT_PROBE,
        "backend": "netsh advfirewall" if platform.system() == "Windows" else "iptables",
        "enforced_count": len(_enforced),
        "intended_count": len(_intended),
        "note": (
            ""
            if _ENFORCEMENT_PROBE
            else "Firewall not programmable (needs elevated privileges). "
                 "Blocks are recorded but NOT enforced."
        ),
    }


def block_ip(ip: str) -> dict:
    """
    Returns {"intended": bool, "enforced": bool, "error": str}.
    `enforced` is true only when an OS firewall rule really exists.
    """
    if ip in WHITELIST:
        log.info("Skip block — whitelisted %s", ip)
        return {"intended": False, "enforced": False, "error": "whitelisted"}
    if not is_valid_ip(ip):
        return {"intended": False, "enforced": False, "error": "invalid IP address"}

    _intended.add(ip)
    ok, err = _add_rule(ip)
    if ok:
        _enforced.add(ip)
        log.warning("BLOCKED %s (firewall rule active)", ip)
        return {"intended": True, "enforced": True, "error": ""}

    _enforced.discard(ip)
    log.error("Block for %s recorded but NOT enforced: %s", ip, err)
    return {"intended": True, "enforced": False, "error": err}


def unblock_ip(ip: str) -> dict:
    ok, err = _delete_rule(ip)
    _intended.discard(ip)
    _enforced.discard(ip)
    if ok:
        log.warning("UNBLOCKED %s", ip)
        return {"released": True, "enforced": True, "error": ""}
    log.error("Firewall rule removal for %s failed: %s", ip, err)
    return {"released": True, "enforced": False, "error": err}


def sync_from_db(active_ips: list[str]) -> None:
    """
    Rebuild in-memory state at startup. Rules from a previous run do not
    survive a reboot, so nothing is assumed enforced until re-applied.
    """
    _intended.clear()
    _enforced.clear()
    for ip in active_ips:
        if ip in WHITELIST or not is_valid_ip(ip):
            continue
        _intended.add(ip)
        ok, _ = _add_rule(ip)
        if ok:
            _enforced.add(ip)
    if _intended and not _enforced:
        log.warning(
            "%d blocklist entries restored but none could be enforced — "
            "firewall changes need elevated privileges.",
            len(_intended),
        )
