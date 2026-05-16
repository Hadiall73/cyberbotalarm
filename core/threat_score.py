"""
Threat Score 0-100:
  0-25  → Low    (Scanner / Neugierde)
  26-50 → Medium (Gezielte Versuche)
  51-75 → High   (Aktiver Angreifer)
  76-100→ Critical (Exploit / Malware)
"""

WEIGHTS = {
    "ssh_login_attempt":    10,
    "ssh_shell_command":    15,
    "ssh_dangerous_cmd":    30,
    "ssh_malware_download": 50,
    "web_admin_access":      5,
    "web_sqli":             20,
    "web_xss":              15,
    "web_rce_attempt":      40,
    "web_path_traversal":   20,
    "port_scan":             8,
    "honeytoken_triggered": 35,
    "is_tor":               15,
    "is_vpn":                5,
    "abuse_score_high":     20,
    "multiple_services":    10,
}

def calculate(events: list[str], geo: dict = None, abuse_score: int = 0) -> int:
    score = 0
    for e in events:
        score += WEIGHTS.get(e, 0)
    if geo:
        if geo.get("is_tor"):
            score += WEIGHTS["is_tor"]
        if geo.get("is_vpn"):
            score += WEIGHTS["is_vpn"]
    if abuse_score > 50:
        score += WEIGHTS["abuse_score_high"]
    return min(score, 100)

def severity_from_score(score: int) -> str:
    if score >= 76: return "critical"
    if score >= 51: return "high"
    if score >= 26: return "medium"
    return "low"

def classify_event_severity(event_type: str) -> str:
    high = {"ssh_malware_download", "web_rce_attempt", "honeytoken_triggered", "ssh_dangerous_cmd"}
    medium = {"ssh_shell_command", "web_sqli", "web_xss", "web_path_traversal"}
    if event_type in high: return "high"
    if event_type in medium: return "medium"
    return "low"
