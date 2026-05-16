import httpx
import re
from datetime import datetime

SEV = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "💀"}
TYPE_ICON = {
    "ssh_login_attempt":    "🔐", "ssh_shell_command":  "💻",
    "ssh_dangerous_cmd":    "☠️", "ssh_malware_download":"🦠",
    "web_admin_access":     "🌐", "web_sqli":           "💉",
    "web_xss":              "⚠️", "web_rce_attempt":    "💣",
    "web_path_traversal":   "📂", "web_sensitive_file": "🗝️",
    "web_fingerprint":      "🔍", "honeytoken_triggered":"🎯",
    "mysql_auth":           "🗄️", "ftp_auth":           "📁",
    "redis_probe":          "🔄", "telnet_auth":        "📟",
    "port_scan":            "🚨",
}

def _esc(text: str) -> str:
    return re.sub(r'([_*\[\]()~`>#+\-=|{}.!\\])', r'\\\1', str(text))

async def send_alert(token: str, chat_id: str, event: dict):
    if not token or not chat_id:
        return

    etype     = event.get("event_type", "unknown")
    ip        = event.get("ip", "?")
    severity  = event.get("severity", "low")
    score     = event.get("threat_score", 0)
    geo       = event.get("geo") or {}
    real_ips  = event.get("real_ips", [])

    flag = {"DE":"🇩🇪","TR":"🇹🇷","RU":"🇷🇺","CN":"🇨🇳","US":"🇺🇸","IR":"🇮🇷","BR":"🇧🇷","IN":"🇮🇳"}.get(
        geo.get("country_code",""), "🌍")

    icon = TYPE_ICON.get(etype, "🪤")
    lines = [
        f"{icon} *{_esc(etype.upper().replace('_',' '))}*  {SEV.get(severity,'🟡')}",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🕐 `{datetime.utcnow().strftime('%d\\.%m\\.%Y %H:%M:%S')} UTC`",
        f"🌍 IP: `{_esc(ip)}`  {flag} {_esc(geo.get('city','?'))}, {_esc(geo.get('country','?'))}",
        f"🏢 ISP: `{_esc(geo.get('isp','?'))}`",
        f"⚡ Score: `{score}/100`",
    ]

    if geo.get("is_tor"):   lines.append("🧅 *TOR EXIT NODE erkannt\\!*")
    if geo.get("is_vpn"):   lines.append("🛡️ *VPN/Proxy erkannt\\!*")
    if real_ips:            lines.append(f"🎯 Echte IP\\(s\\): `{_esc(', '.join(real_ips))}`")
    if event.get("username"): lines.append(f"👤 User: `{_esc(event['username'])}`")
    if event.get("password"): lines.append(f"🔑 Pass: `{_esc(event['password'])}`")
    if event.get("command"):  lines.append(f"💻 CMD: `{_esc(str(event['command'])[:200])}`")
    if event.get("payload"):  lines.append(f"📦 Payload: `{_esc(str(event['payload'])[:200])}`")
    if event.get("tools_detected"):
        lines.append(f"🛠 Tool: `{_esc(', '.join(event['tools_detected']))}`")
    if etype == "honeytoken_triggered":
        lines.append(f"🎯 *HONEYTOKEN ausgelöst\\!* Label: `{_esc(event.get('label','?'))}`")

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("🪤 *CyberBotAlarm Honeypot*")

    text = "\n".join(lines)
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"},
        )
