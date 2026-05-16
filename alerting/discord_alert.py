import httpx
from datetime import datetime

COLORS = {"low": 0xFFFF00, "medium": 0xFF8C00, "high": 0xFF0000, "critical": 0x8B0000}

async def send_alert(webhook_url: str, event: dict):
    if not webhook_url:
        return
    geo = event.get("geo") or {}
    severity = event.get("severity", "low")
    score = event.get("threat_score", 0)

    fields = [
        {"name": "🌍 IP", "value": f"`{event.get('ip','?')}`", "inline": True},
        {"name": "📍 Location", "value": f"{geo.get('city','?')}, {geo.get('country','?')}", "inline": True},
        {"name": "⚡ Score", "value": f"`{score}/100`", "inline": True},
        {"name": "🏢 ISP", "value": f"`{geo.get('isp','?')}`", "inline": True},
        {"name": "🔒 TOR/VPN", "value": f"{'🧅 TOR' if geo.get('is_tor') else ''} {'🛡️ VPN' if geo.get('is_vpn') else ''} {'–' if not geo.get('is_tor') and not geo.get('is_vpn') else ''}", "inline": True},
        {"name": "🔥 Severity", "value": severity.upper(), "inline": True},
    ]
    if event.get("username"):
        fields.append({"name": "👤 Username", "value": f"`{event['username']}`", "inline": True})
    if event.get("password"):
        fields.append({"name": "🔑 Password", "value": f"`{event['password']}`", "inline": True})
    if event.get("command"):
        fields.append({"name": "💻 Command", "value": f"```{str(event['command'])[:500]}```", "inline": False})
    if event.get("real_ips"):
        fields.append({"name": "🎯 Real IPs (WebRTC Leak)", "value": f"`{', '.join(event['real_ips'])}`", "inline": False})
    if event.get("tools_detected"):
        fields.append({"name": "🛠 Tools", "value": f"`{', '.join(event['tools_detected'])}`", "inline": True})

    etype = event.get("event_type","?").upper().replace("_"," ")
    payload = {
        "embeds": [{
            "title": f"🪤 {etype}",
            "color": COLORS.get(severity, 0xFFFF00),
            "fields": fields,
            "footer": {"text": f"CyberBotAlarm • {datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC"},
        }]
    }
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(webhook_url, json=payload)
