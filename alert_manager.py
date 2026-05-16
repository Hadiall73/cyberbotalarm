import asyncio
import logging
from datetime import datetime, timedelta
from database import log_event, get_events, get_stats
from alerting import telegram_alert, discord_alert, email_alert

logger = logging.getLogger("alert_manager")


class AlertManager:
    def __init__(self, config: dict):
        self.config = config
        self._cooldowns: dict[str, datetime] = {}
        self._ws_clients: list = []

    def register_ws(self, ws):
        self._ws_clients.append(ws)

    def unregister_ws(self, ws):
        self._ws_clients.discard(ws) if hasattr(self._ws_clients, 'discard') else None
        if ws in self._ws_clients:
            self._ws_clients.remove(ws)

    async def trigger(self, event: dict):
        ip = event.get("ip", "unknown")
        event_type = event.get("event_type", "unknown")
        cooldown_key = f"{ip}:{event_type}"

        now = datetime.utcnow()
        cooldown_sec = self.config.get("alerts", {}).get("cooldown_seconds", 30)
        if cooldown_key in self._cooldowns:
            if now - self._cooldowns[cooldown_key] < timedelta(seconds=cooldown_sec):
                return

        self._cooldowns[cooldown_key] = now

        log_event(
            event_type=event_type,
            ip=ip,
            port=event.get("port"),
            username=event.get("username"),
            password=event.get("password"),
            payload=event.get("payload"),
            severity=event.get("severity", "low"),
        )

        logger.warning(f"[ALARM] {event_type} von {ip}")

        tg = self.config.get("telegram", {})
        discord = self.config.get("discord", {})
        mail = self.config.get("email", {})

        await asyncio.gather(
            telegram_alert.send_alert(tg.get("token", ""), tg.get("chat_id", ""), event),
            discord_alert.send_alert(discord.get("webhook_url", ""), event),
            email_alert.send_alert(
                mail.get("smtp_server", "smtp.gmail.com"),
                mail.get("smtp_port", 587),
                mail.get("sender", ""),
                mail.get("password", ""),
                mail.get("receiver", ""),
                event,
            ),
            self._broadcast_ws(event),
            return_exceptions=True,
        )

    async def _broadcast_ws(self, event: dict):
        import json
        dead = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)
