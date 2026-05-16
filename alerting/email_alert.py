import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

async def send_alert(smtp_server: str, smtp_port: int, sender: str,
                     password: str, receiver: str, event: dict):
    if not sender or not password or not receiver:
        return

    subject = f"[HONEYPOT] {event.get('event_type', 'Alarm').upper()} von {event.get('ip', '?')}"

    html = f"""
    <html><body style="font-family: monospace; background: #1a1a1a; color: #00ff00; padding: 20px;">
    <h2 style="color: #ff4444;">🪤 HONEYPOT ALARM</h2>
    <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Zeitpunkt</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Typ</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('event_type', '?')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>IP</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('ip', '?')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Port</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('port', '-')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Username</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('username', '-')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Password</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('password', '-')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Payload</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('payload', '-')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #333;"><b>Severity</b></td>
            <td style="padding: 8px; border: 1px solid #333;">{event.get('severity', 'low').upper()}</td></tr>
    </table>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver
    msg.attach(MIMEText(html, "html"))

    def _send():
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())

    await asyncio.get_event_loop().run_in_executor(None, _send)
