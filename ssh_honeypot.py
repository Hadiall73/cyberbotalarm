import asyncio
import logging
import socket
import threading
import paramiko
from datetime import datetime

logger = logging.getLogger("ssh_honeypot")

HOST_KEY = paramiko.RSAKey.generate(2048)

FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, on_auth):
        self.client_ip = client_ip
        self.on_auth = on_auth
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        self.on_auth(self.client_ip, username, password)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


async def start_ssh_honeypot(host: str, port: int, alert_manager):
    loop = asyncio.get_event_loop()

    def handle_client(client_sock, client_addr):
        ip = client_addr[0]
        logger.info(f"SSH Verbindung von {ip}")

        def on_auth(ip, username, password):
            event = {
                "event_type": "ssh_login",
                "ip": ip,
                "port": port,
                "username": username,
                "password": password,
                "severity": "high",
            }
            asyncio.run_coroutine_threadsafe(alert_manager.trigger(event), loop)

        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = FAKE_BANNER
            transport.add_server_key(HOST_KEY)
            server = HoneypotSSHServer(ip, on_auth)
            transport.start_server(server=server)

            chan = transport.accept(20)
            if chan:
                chan.send("Permission denied\r\n")
                chan.close()
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def run_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        logger.info(f"SSH Honeypot läuft auf {host}:{port}")
        while True:
            try:
                client, addr = sock.accept()
                t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
                t.start()
            except Exception:
                break

    await loop.run_in_executor(None, run_server)
