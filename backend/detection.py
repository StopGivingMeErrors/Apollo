"""Detection rules — MITRE ATT&CK mapping and risk scoring."""
from __future__ import annotations

MITRE_MAP: dict[str, dict] = {
    "SSH Brute Force": {
        "technique": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "SSH Probe": {
        "technique": "T1595.001",
        "name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
    },
    "SQL Injection": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "Web Scanner": {
        "technique": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
    "Path Traversal": {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "HTTP Probe": {
        "technique": "T1595.001",
        "name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
    },
    "FTP Auth Attempt": {
        "technique": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "FTP Anonymous Access": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "Telnet Login Attempt": {
        "technique": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
}

SEVERITY_WEIGHT = {"low": 15, "medium": 35, "high": 60, "critical": 85}


def mitre_for(threat_type: str) -> dict:
    return MITRE_MAP.get(
        threat_type,
        {"technique": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    )


def risk_score(
    *,
    severity: str,
    hits: int,
    port_count: int = 1,
    intel_tags: list[str] | None = None,
    country: str = "",
) -> int:
    """Compute 0–100 risk score for an attacker IP / alert."""
    score = SEVERITY_WEIGHT.get(severity, 20)
    score += min(hits * 2, 25)
    if port_count >= 2:
        score += 15
    if port_count >= 3:
        score += 10
    tags = intel_tags or []
    if "tor" in tags:
        score += 12
    if "known_scanner" in tags:
        score += 15
    if "vpn" in tags:
        score += 5
    # Slight bump for high-volume attack origins often seen in honeypot traffic
    if country in {"Russia", "China", "Iran", "North Korea"}:
        score += 5
    return max(0, min(100, int(score)))


def alert_title(threat_type: str, ip: str, event_count: int = 1) -> str:
    if event_count > 1:
        return f"{threat_type} from {ip} ({event_count} events)"
    return f"{threat_type} from {ip}"
