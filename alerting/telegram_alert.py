import httpx
from datetime import datetime

ICONS = {
    "ssh_login": "🔐",
    "web_admin": "🌐",
    "web_sqli": "💉",
    "web_xss": "⚠️",
    "web_scan": "🔍",
    "port_scan": "🚨",
    "default": "🪤",
}

SEVERITY_EMOJI = {"low": "🟡", "medium": "🟠", "high": "🔴"}

async def send_alert(token: str, chat_id: str, event: dict):
    icon = ICONS.get(event.get("event_type"), ICONS["default"])
    severity = event.get("severity", "low")
    sev_emoji = SEVERITY_EMOJI.get(severity, "🟡")

    lines = [
        f"{icon} *HONEYPOT ALARM* {sev_emoji}",
        f"━━━━━━━━━━━━━━━━━━━",
        f"🕐 `{datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC`",
        f"📌 Typ: `{event.get('event_type', 'unbekannt')}`",
        f"🌍 IP: `{event.get('ip', '?')}`",
    ]

    if event.get("port"):
        lines.append(f"🔌 Port: `{event['port']}`")
    if event.get("username"):
        lines.append(f"👤 User: `{event['username']}`")
    if event.get("password"):
        lines.append(f"🔑 Pass: `{event['password']}`")
    if event.get("payload"):
        lines.append(f"📦 Payload: `{event['payload'][:200]}`")

    lines.append(f"━━━━━━━━━━━━━━━━━━━")
    lines.append(f"⚡ *Dein Honeypot hat ihn erwischt\\!*")

    text = "\n".join(lines)

    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"},
            timeout=10,
        )
