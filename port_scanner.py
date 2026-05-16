import asyncio
import logging

logger = logging.getLogger("port_scanner")


async def handle_port(reader, writer, port: int, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    logger.info(f"Port-Scan erkannt: {ip} → Port {port}")

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        payload = data.decode(errors="ignore").strip()
    except asyncio.TimeoutError:
        payload = ""

    event = {
        "event_type": "port_scan",
        "ip": ip,
        "port": port,
        "payload": payload or f"Verbindung auf Port {port}",
        "severity": "medium",
    }
    await alert_manager.trigger(event)
    writer.close()


async def start_port_honeypot(host: str, ports: list[int], alert_manager):
    servers = []
    for port in ports:
        try:
            server = await asyncio.start_server(
                lambda r, w, p=port: handle_port(r, w, p, alert_manager),
                host, port
            )
            servers.append(server)
            logger.info(f"Port-Listener aktiv auf {host}:{port}")
        except OSError as e:
            logger.warning(f"Port {port} nicht verfügbar: {e}")

    if servers:
        await asyncio.gather(*[s.serve_forever() for s in servers])
