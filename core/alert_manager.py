import asyncio
import json
import logging
from datetime import datetime, timedelta
from core import database as db
from core.ip_intel import get_ip_info, get_abuse_score
from core import threat_score as ts
from alerting import telegram_alert, discord_alert, email_alert

logger = logging.getLogger("alert_manager")


class AlertManager:
    def __init__(self, config: dict):
        self.cfg = config
        self._cooldowns: dict[str, datetime] = {}
        self._ws: list = []
        self._attacker_events: dict[str, list[str]] = {}

    def register_ws(self, ws): self._ws.append(ws)
    def unregister_ws(self, ws):
        if ws in self._ws: self._ws.remove(ws)

    async def trigger(self, event_type: str, ip: str, port: int = None, data: dict = None, force: bool = False):
        data = data or {}
        cooldown_key = f"{ip}:{event_type}"
        cooldown_sec = self.cfg.get("alerts", {}).get("cooldown_seconds", 20)
        now = datetime.utcnow()

        if not force and cooldown_key in self._cooldowns:
            if now - self._cooldowns[cooldown_key] < timedelta(seconds=cooldown_sec):
                return
        self._cooldowns[cooldown_key] = now

        severity = ts.classify_event_severity(event_type)
        db.log_event(event_type, ip, port, severity, data)

        if ip not in self._attacker_events:
            self._attacker_events[ip] = []
        self._attacker_events[ip].append(event_type)

        geo = await get_ip_info(ip)
        abuse = await get_abuse_score(ip, self.cfg.get("abuseipdb_key", ""))

        score = ts.calculate(self._attacker_events[ip], geo, abuse)
        db.upsert_attacker(ip, geo=geo, threat_score=score)

        alert = {
            "event_type":   event_type,
            "ip":           ip,
            "port":         port,
            "severity":     severity,
            "threat_score": score,
            "geo":          geo,
            "abuse_score":  abuse,
            "ts":           now.isoformat(),
            **data,
        }

        logger.warning(f"[{severity.upper()}] {event_type} | {ip} | Score:{score} | {geo.get('country','?')}")

        tg  = self.cfg.get("telegram", {})
        dc  = self.cfg.get("discord", {})
        mail = self.cfg.get("email", {})

        await asyncio.gather(
            telegram_alert.send_alert(tg.get("token",""), tg.get("chat_id",""), alert),
            discord_alert.send_alert(dc.get("webhook_url",""), alert),
            email_alert.send_alert(mail, alert),
            self._broadcast(alert),
            return_exceptions=True,
        )

        if score >= self.cfg.get("alerts", {}).get("autoblock_score", 80):
            db.upsert_attacker(ip, blocked=1)
            logger.warning(f"AUTO-BLOCK: {ip} (Score {score})")

    async def _broadcast(self, event: dict):
        dead = []
        msg = json.dumps({"type": "event", **event})
        for ws in self._ws:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister_ws(ws)
