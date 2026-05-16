import asyncio
import socket
import threading
import logging
import paramiko
from honeypots.ssh.fake_shell import FakeShell
from core import database as db

logger = logging.getLogger("ssh_honeypot")
HOST_KEY = paramiko.RSAKey.generate(2048)


class _Server(paramiko.ServerInterface):
    def __init__(self, ip, on_auth, on_shell):
        self.ip = ip
        self.on_auth = on_auth
        self.on_shell = on_shell
        self.username = "root"
        self.password = ""
        self._event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.on_auth(self.ip, username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self._event.set()
        return True

    def check_channel_pty_request(self, ch, term, w, h, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self._event.set()
        return True


def _handle(client_sock, addr, loop, alert_manager, tokens):
    ip = addr[0]
    logger.info(f"SSH Verbindung: {ip}")

    def on_auth(ip, user, pw):
        asyncio.run_coroutine_threadsafe(
            alert_manager.trigger("ssh_login_attempt", ip, 2222, {
                "username": user, "password": pw
            }), loop
        )

    def on_shell_event(etype, data):
        return asyncio.run_coroutine_threadsafe(
            alert_manager.trigger(etype, ip, 2222, data), loop
        )

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(HOST_KEY)

        server_obj = _Server(ip, on_auth, None)
        transport.start_server(server=server_obj)

        channel = transport.accept(30)
        if not channel:
            return

        server_obj._event.wait(10)

        sid = db.new_session(ip, "ssh")

        async def async_on_event(etype, data):
            await alert_manager.trigger(etype, ip, 2222, data)

        shell = FakeShell(ip, server_obj.username, tokens, sid, async_on_event)

        async def run():
            cmds = await shell.run(channel)
            db.update_session(sid, commands=cmds, credentials={"username": server_obj.username, "password": server_obj.password})
            db.close_session(sid)

        future = asyncio.run_coroutine_threadsafe(run(), loop)
        future.result(timeout=300)

    except Exception as e:
        logger.debug(f"SSH Fehler {ip}: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


async def start(host: str, port: int, alert_manager, tokens: dict):
    loop = asyncio.get_event_loop()

    def serve():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(50)
        logger.info(f"SSH Honeypot aktiv: {host}:{port}")
        while True:
            try:
                client, addr = sock.accept()
                t = threading.Thread(target=_handle, args=(client, addr, loop, alert_manager, tokens), daemon=True)
                t.start()
            except Exception:
                break

    await loop.run_in_executor(None, serve)
