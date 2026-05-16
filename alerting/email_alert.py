import asyncio, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

async def send_alert(cfg: dict, event: dict):
    sender   = cfg.get("sender","")
    password = cfg.get("password","")
    receiver = cfg.get("receiver","")
    if not all([sender, password, receiver]):
        return

    geo      = event.get("geo") or {}
    score    = event.get("threat_score", 0)
    severity = event.get("severity","low")
    etype    = event.get("event_type","?")
    ip       = event.get("ip","?")

    color = {"low":"#f59e0b","medium":"#f97316","high":"#ef4444","critical":"#7f1d1d"}.get(severity,"#f59e0b")

    rows = ""
    for k, v in {
        "Event Type": etype, "IP Address": ip,
        "Location": f"{geo.get('city','?')}, {geo.get('country','?')}",
        "ISP": geo.get("isp","?"), "TOR": "YES" if geo.get("is_tor") else "No",
        "VPN/Proxy": "YES" if geo.get("is_vpn") else "No",
        "Threat Score": f"{score}/100", "Severity": severity.upper(),
        "Username": event.get("username","–"), "Password": event.get("password","–"),
        "Command": event.get("command","–"), "Payload": event.get("payload","–"),
        "Real IPs": ", ".join(event.get("real_ips",[]) or []) or "–",
        "Tools": ", ".join(event.get("tools_detected",[]) or []) or "–",
    }.items():
        rows += f"<tr><td style='padding:8px;color:#94a3b8;border-bottom:1px solid #1e293b'>{k}</td><td style='padding:8px;color:#e2e8f0;border-bottom:1px solid #1e293b'>{v}</td></tr>"

    html = f"""
    <html><body style="background:#0f1117;margin:0;padding:20px;font-family:monospace">
    <div style="max-width:600px;margin:auto;background:#1a1d27;border-radius:12px;overflow:hidden">
      <div style="background:{color};padding:20px">
        <h2 style="margin:0;color:#fff">🪤 HONEYPOT ALARM — {etype.upper().replace('_',' ')}</h2>
        <p style="margin:4px 0 0;color:rgba(255,255,255,0.8);font-size:0.85rem">{datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC</p>
      </div>
      <table style="width:100%;border-collapse:collapse">{rows}</table>
      <div style="padding:16px;text-align:center;color:#475569;font-size:0.75rem">CyberBotAlarm Honeypot System</div>
    </div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[HONEYPOT {severity.upper()}] {etype} von {ip}"
    msg["From"]    = sender
    msg["To"]      = receiver
    msg.attach(MIMEText(html, "html"))

    def _send():
        with smtplib.SMTP(cfg.get("smtp_server","smtp.gmail.com"), cfg.get("smtp_port",587)) as s:
            s.starttls()
            s.login(sender, password)
            s.sendmail(sender, receiver, msg.as_string())

    try:
        await asyncio.get_event_loop().run_in_executor(None, _send)
    except Exception:
        pass
