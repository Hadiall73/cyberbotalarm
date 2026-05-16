"""Fake Service Honeypots: MySQL, FTP, Redis, Telnet"""
import asyncio
import logging

logger = logging.getLogger("services")

# ── MySQL ──────────────────────────────────────────────────────────────
async def _mysql_client(reader, writer, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    try:
        # Send fake MySQL handshake
        handshake = (
            b"\x4a\x00\x00\x00"           # packet length
            b"\x0a"                         # protocol version 10
            b"8.0.35-Ubuntu\x00"            # server version
            b"\x08\x00\x00\x00"            # connection id
            b"\x52\x67\x34\x58\x6c\x6a\x6f\x4f\x00"  # auth data
            b"\xff\xf7"                     # capability flags
            b"\x21"                         # character set
            b"\x02\x00"                     # status flags
            b"\xff\xff"                     # capability flags ext
            b"\x15"                         # auth plugin data length
            b"\x00" * 10                    # reserved
            b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32\x00"
            b"mysql_native_password\x00"
        )
        writer.write(handshake)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=5)
        if data:
            try:
                creds_raw = data[36:].split(b"\x00")
                username = creds_raw[0].decode(errors="ignore") if creds_raw else ""
                password = creds_raw[1].decode(errors="ignore") if len(creds_raw) > 1 else ""
            except Exception:
                username, password = "", ""

            await alert_manager.trigger("mysql_auth", ip, 3306, {
                "username": username, "password": password
            })

        # Send auth failure
        writer.write(b"\x2b\x00\x00\x02\xff\x15\x04Access denied for user")
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

# ── FTP ───────────────────────────────────────────────────────────────
async def _ftp_client(reader, writer, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    username = ""
    try:
        writer.write(b"220 ProFTPD 1.3.8 Server (Ubuntu FTP) [172.31.42.100]\r\n")
        await writer.drain()

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line:
                break
            cmd = line.decode(errors="ignore").strip()
            if cmd.upper().startswith("USER"):
                username = cmd[5:].strip()
                writer.write(b"331 Password required for " + username.encode() + b"\r\n")
            elif cmd.upper().startswith("PASS"):
                password = cmd[5:].strip()
                await alert_manager.trigger("ftp_auth", ip, 21, {
                    "username": username, "password": password
                })
                writer.write(b"530 Login incorrect.\r\n")
            elif cmd.upper() == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                break
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

# ── Redis ─────────────────────────────────────────────────────────────
async def _redis_client(reader, writer, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=5)
        payload = data.decode(errors="ignore").strip()

        await alert_manager.trigger("redis_probe", ip, 6379, {
            "payload": payload[:200]
        })

        if "AUTH" in payload.upper():
            writer.write(b"-ERR invalid password\r\n")
        elif "INFO" in payload.upper():
            writer.write(b"$1024\r\n# Server\r\nredis_version:7.2.3\r\nos:Linux 5.15.0\r\narch_bits:64\r\n\r\n")
        else:
            writer.write(b"-NOAUTH Authentication required.\r\n")
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

# ── Telnet ────────────────────────────────────────────────────────────
async def _telnet_client(reader, writer, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    username = ""
    try:
        writer.write(b"\r\nUbuntu 22.04.3 LTS\r\nubuntu-server login: ")
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=10)
        username = line.decode(errors="ignore").strip()

        writer.write(b"Password: ")
        await writer.drain()

        line2 = await asyncio.wait_for(reader.readline(), timeout=10)
        password = line2.decode(errors="ignore").strip()

        await alert_manager.trigger("telnet_auth", ip, 23, {
            "username": username, "password": password
        })

        writer.write(b"\r\nLogin incorrect\r\n\r\nubuntu-server login: ")
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

# ── Port Scan Detector ────────────────────────────────────────────────
async def _port_client(reader, writer, port, alert_manager):
    ip = writer.get_extra_info("peername")[0]
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=3)
        payload = data.decode(errors="ignore").strip() if data else ""
    except asyncio.TimeoutError:
        payload = ""
    await alert_manager.trigger("port_scan", ip, port, {"payload": payload})
    writer.close()

# ── Starter ───────────────────────────────────────────────────────────
async def start_all(host: str, config: dict, alert_manager):
    hp = config.get("honeypot", {})
    servers = []

    service_map = {
        "mysql_port":  (3306, lambda r,w: _mysql_client(r, w, alert_manager)),
        "ftp_port":    (21,   lambda r,w: _ftp_client(r, w, alert_manager)),
        "redis_port":  (6379, lambda r,w: _redis_client(r, w, alert_manager)),
        "telnet_port": (23,   lambda r,w: _telnet_client(r, w, alert_manager)),
    }

    for key, (default_port, handler) in service_map.items():
        port = hp.get(key, default_port)
        try:
            srv = await asyncio.start_server(handler, host, port)
            servers.append(srv)
            logger.info(f"Service Honeypot aktiv: {host}:{port} ({key})")
        except OSError as e:
            logger.warning(f"Port {port} nicht verfügbar: {e}")

    # Extra Port-Scan Traps
    for port in hp.get("scan_ports", [25, 8888, 9200, 5432, 27017]):
        try:
            p = port
            srv = await asyncio.start_server(
                lambda r, w, port=p: _port_client(r, w, port, alert_manager),
                host, p
            )
            servers.append(srv)
            logger.info(f"Port-Trap aktiv: {host}:{p}")
        except OSError:
            pass

    if servers:
        await asyncio.gather(*[s.serve_forever() for s in servers])
