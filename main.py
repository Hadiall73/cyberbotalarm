import asyncio
import logging
import yaml
from pathlib import Path

from core.database import init_db
from core.alert_manager import AlertManager
from core.ip_intel import load_tor_nodes
from core.honeytokens import generate_tokens
from honeypots.ssh.server import start as start_ssh
from honeypots.web.server import start as start_web
from honeypots.services import start_all as start_services
from dashboard.app import start as start_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-16s] %(levelname)s: %(message)s",
    datefmt="%d.%m.%Y %H:%M:%S",
)
logger = logging.getLogger("main")


def load_config() -> dict:
    path = Path("config.yml")
    if not path.exists():
        raise FileNotFoundError("config.yml fehlt! Kopiere config.example.yml → config.yml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


async def main():
    config = load_config()
    init_db()
    await load_tor_nodes()
    tokens = generate_tokens()

    am = AlertManager(config)
    hp = config.get("honeypot", {})
    host = "0.0.0.0"

    ssh_port  = hp.get("ssh_port", 2222)
    web_port  = hp.get("web_port", 8080)
    dash_port = hp.get("dashboard_port", 9999)

    logger.info("=" * 55)
    logger.info("  🪤  CyberBotAlarm — High-Level Honeypot System")
    logger.info("=" * 55)
    logger.info(f"  SSH Honeypot     → :{ssh_port}  (Fake Shell aktiv)")
    logger.info(f"  Web Honeypot     → :{web_port}  (WebRTC + Fingerprint)")
    logger.info(f"  Service Traps    → MySQL/FTP/Redis/Telnet")
    logger.info(f"  Dashboard        → http://localhost:{dash_port}")
    logger.info(f"  Telegram Bot     → @Cyberalarm_37bot")
    logger.info(f"  Honeytokens      → {len(tokens)} aktiv")
    logger.info("=" * 55)

    await asyncio.gather(
        start_ssh(host, ssh_port, am, tokens),
        start_web(host, web_port, am, tokens),
        start_services(host, config, am),
        start_dashboard(host, dash_port, am),
    )


if __name__ == "__main__":
    asyncio.run(main())
