import asyncio
import logging
import yaml
from pathlib import Path

from database import init_db
from alert_manager import AlertManager
from ssh_honeypot import start_ssh_honeypot
from web_honeypot import start_web_honeypot
from port_scanner import start_port_honeypot
from dashboard.app import start_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%d.%m.%Y %H:%M:%S",
)
logger = logging.getLogger("main")


def load_config() -> dict:
    path = Path("config.yml")
    if not path.exists():
        raise FileNotFoundError("config.yml nicht gefunden!")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


async def main():
    config = load_config()
    init_db()

    alert_manager = AlertManager(config)
    hp = config.get("honeypot", {})

    host = "0.0.0.0"
    ssh_port = hp.get("ssh_port", 2222)
    web_port = hp.get("web_port", 8080)
    dash_port = hp.get("dashboard_port", 9999)
    scan_ports = hp.get("scan_ports", [21, 23, 25, 3306])

    logger.info("🪤 CyberBotAlarm startet...")
    logger.info(f"   SSH Honeypot    → Port {ssh_port}")
    logger.info(f"   Web Honeypot    → Port {web_port}")
    logger.info(f"   Port Listener   → {scan_ports}")
    logger.info(f"   Dashboard       → http://localhost:{dash_port}")

    await asyncio.gather(
        start_ssh_honeypot(host, ssh_port, alert_manager),
        start_web_honeypot(host, web_port, alert_manager),
        start_port_honeypot(host, scan_ports, alert_manager),
        start_dashboard(host, dash_port, alert_manager),
    )


if __name__ == "__main__":
    asyncio.run(main())
