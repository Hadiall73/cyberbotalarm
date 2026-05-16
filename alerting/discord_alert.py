import httpx
from datetime import datetime

COLORS = {"low": 0xFFFF00, "medium": 0xFF8C00, "high": 0xFF0000}

async def send_alert(webhook_url: str, event: dict):
    if not webhook_url:
        return

    severity = event.get("severity", "low")
    fields = [
        {"name": "IP-Adresse", "value": f"`{event.get('ip', '?')}`", "inline": True},
        {"name": "Typ", "value": f"`{event.get('event_type', '?')}`", "inline": True},
        {"name": "Severity", "value": severity.upper(), "inline": True},
    ]
    if event.get("port"):
        fields.append({"name": "Port", "value": str(event["port"]), "inline": True})
    if event.get("username"):
        fields.append({"name": "Username", "value": f"`{event['username']}`", "inline": True})
    if event.get("password"):
        fields.append({"name": "Password", "value": f"`{event['password']}`", "inline": True})
    if event.get("payload"):
        fields.append({"name": "Payload", "value": f"```{event['payload'][:500]}```", "inline": False})

    payload = {
        "embeds": [{
            "title": "🪤 HONEYPOT ALARM",
            "description": f"Ein Angreifer wurde erkannt!",
            "color": COLORS.get(severity, 0xFFFF00),
            "fields": fields,
            "footer": {"text": f"CyberBotAlarm • {datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC"},
        }]
    }

    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload, timeout=10)
