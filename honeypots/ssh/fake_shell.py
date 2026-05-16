"""Interaktive Fake-Bash-Shell — Angreifer denkt er ist root"""
import asyncio
import re
from datetime import datetime
from honeypots.ssh.filesystem import build as build_fs

DANGEROUS_CMDS = {"wget", "curl", "python", "python3", "perl", "ruby", "nc", "ncat", "bash -i", "sh -i", "chmod", "rm -rf"}
MALWARE_PATTERNS = [r"pastebin\.com", r"\.sh$", r"base64\s+-d", r"/dev/tcp", r"xmrig", r"miner"]


class FakeShell:
    def __init__(self, ip: str, username: str, tokens: dict, session_id: int, on_event):
        self.ip = ip
        self.username = username
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.fs = build_fs(tokens)
        self.session_id = session_id
        self.on_event = on_event
        self.commands: list[dict] = []
        self.hostname = "ubuntu-server"

    def _prompt(self) -> bytes:
        user = self.username
        color_user = f"\033[01;32m{user}@{self.hostname}\033[00m"
        color_path = f"\033[01;34m{self.cwd}\033[00m"
        symbol = "#" if user == "root" else "$"
        return f"{color_user}:{color_path}{symbol} ".encode()

    def _resolve(self, path: str) -> str:
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        parts = self.cwd.split("/") + path.split("/")
        resolved = []
        for p in parts:
            if p == "..":
                if resolved: resolved.pop()
            elif p and p != ".":
                resolved.append(p)
        return "/" + "/".join(resolved)

    def _ls(self, path: str, long: bool = False) -> str:
        target = self._resolve(path) if path else self.cwd
        entry = self.fs.get(target)
        if entry is None:
            return f"ls: cannot access '{path}': No such file or directory\n"
        if isinstance(entry, list):
            if long:
                lines = ["total " + str(len(entry) * 4)]
                for name in entry:
                    fp = target.rstrip("/") + "/" + name
                    is_dir = isinstance(self.fs.get(fp), list)
                    perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    lines.append(f"{perm} 1 root root  4096 May 15 12:00 {name}")
                return "\n".join(lines) + "\n"
            return "  ".join(entry) + "\n"
        return f"ls: {target}: Not a directory\n"

    def _cat(self, path: str) -> str:
        target = self._resolve(path)
        content = self.fs.get(target)
        if content is None:
            return f"cat: {path}: No such file or directory\n"
        if isinstance(content, list):
            return f"cat: {path}: Is a directory\n"
        return content

    def _cd(self, path: str) -> str:
        target = self._resolve(path) if path else "/root"
        if target in self.fs and isinstance(self.fs[target], list):
            self.cwd = target
            return ""
        return f"bash: cd: {path}: No such file or directory\n"

    def _detect_dangerous(self, cmd: str) -> tuple[bool, str]:
        for dc in DANGEROUS_CMDS:
            if cmd.strip().startswith(dc) or f" {dc}" in cmd:
                return True, dc
        for pattern in MALWARE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return True, "malware_download"
        return False, ""

    async def _handle_cmd(self, raw: str) -> str:
        cmd = raw.strip()
        if not cmd:
            return ""

        ts = datetime.utcnow().isoformat()
        self.commands.append({"ts": ts, "cmd": cmd})

        is_dangerous, danger_type = self._detect_dangerous(cmd)
        if is_dangerous:
            etype = "ssh_malware_download" if "malware" in danger_type else "ssh_dangerous_cmd"
            await self.on_event(etype, {"command": cmd, "session_id": self.session_id})
        else:
            await self.on_event("ssh_shell_command", {"command": cmd, "session_id": self.session_id})

        parts = cmd.split()
        base = parts[0] if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        if base in ("exit", "logout", "quit"):
            return "__EXIT__"
        if base == "clear":
            return "\033[2J\033[H"
        if base == "pwd":
            return self.cwd + "\n"
        if base == "whoami":
            return self.username + "\n"
        if base == "id":
            uid = "0" if self.username == "root" else "1000"
            return f"uid={uid}({self.username}) gid={uid}({self.username}) groups={uid}({self.username})\n"
        if base == "hostname":
            return self.hostname + "\n"
        if base == "uname":
            if "-a" in args:
                return "Linux ubuntu-server 5.15.0-1034-aws #38-Ubuntu SMP Mon Apr 28 13:27:44 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"
        if base == "date":
            return datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"
        if base == "uptime":
            return " 14:23:01 up 47 days,  3:12,  1 user,  load average: 0.08, 0.12, 0.09\n"
        if base == "ls":
            long = "-l" in args or "-la" in args or "-al" in args
            path = next((a for a in args if not a.startswith("-")), "")
            return self._ls(path, long)
        if base == "cd":
            return self._cd(args[0] if args else "")
        if base == "cat":
            if not args: return "cat: missing operand\n"
            return self._cat(args[0])
        if base in ("wget", "curl"):
            url = args[0] if args else ""
            return f"--{datetime.utcnow().strftime('%H:%M:%S')}--  {url}\nResolving {url.split('/')[2] if '/' in url else url}... \nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\n"
        if base == "ps":
            return ("  PID TTY          TIME CMD\n"
                    "    1 ?        00:00:02 systemd\n"
                    "  812 ?        00:00:00 sshd\n"
                    f" 1337 pts/0    00:00:00 {base}\n"
                    " 1338 pts/0    00:00:00 ps\n")
        if base in ("netstat", "ss"):
            return ("Active Internet connections (only servers)\n"
                    "Proto  Local Address    Foreign Address  State\n"
                    "tcp    0.0.0.0:22       0.0.0.0:*        LISTEN\n"
                    "tcp    0.0.0.0:80       0.0.0.0:*        LISTEN\n"
                    "tcp    0.0.0.0:443      0.0.0.0:*        LISTEN\n"
                    "tcp    0.0.0.0:3306     127.0.0.1:*      LISTEN\n")
        if base in ("ifconfig", "ip"):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
                    "      inet 172.31.42.100  netmask 255.255.240.0  broadcast 172.31.47.255\n"
                    "      ether 0a:b2:c3:d4:e5:f6  txqueuelen 1000  (Ethernet)\n")
        if base == "df":
            return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                    "/dev/xvda1       30G   18G   11G  62% /\n"
                    "tmpfs           3.9G     0  3.9G   0% /dev/shm\n")
        if base == "free":
            return ("              total        used        free      shared\n"
                    "Mem:        8192000     4096000     2048000      102400\n"
                    "Swap:       2048000      512000     1536000\n")
        if base == "history":
            hist = self.fs.get("/root/.bash_history", "")
            return "\n".join(f"  {i+1}  {l}" for i, l in enumerate(hist.splitlines())) + "\n"
        if base in ("python", "python3"):
            return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]\nType 'exit()' to quit.\n>>> "
        if base in ("mysql", "psql"):
            return f"Welcome to the MySQL monitor. Commands end with ; or \\g.\nType 'help;' for help.\nmysql> "
        if base == "echo":
            return " ".join(args) + "\n"
        if base in ("nano", "vim", "vi"):
            return f"  GNU nano — {args[0] if args else 'newfile'}\n[Press Ctrl+X to exit]\n"
        if base == "su":
            return "Password: \nsu: Authentication failure\n"
        if base in ("systemctl", "service"):
            return "● nginx.service - A high performance web server\n   Loaded: loaded\n   Active: active (running)\n"
        if base == "env":
            return "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nHOME=/root\nUSER=root\nSHELL=/bin/bash\n"
        if base == "which":
            bins = {"python":"/usr/bin/python3","wget":"/usr/bin/wget","curl":"/usr/bin/curl","nc":"/usr/bin/nc"}
            return bins.get(args[0] if args else "", f"{args[0] if args else ''}: not found\n") + "\n"

        return f"{base}: command not found\n"

    async def run(self, channel):
        channel.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-1034-aws x86_64)\r\n\r\n")
        channel.send(b" * Documentation:  https://help.ubuntu.com\r\n")
        channel.send(b" * Management:     https://landscape.canonical.com\r\n\r\n")
        channel.send(b"Last login: Wed May 15 09:12:34 2024 from 10.0.0.5\r\n\r\n")
        channel.send(self._prompt())

        buf = ""
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break
                for byte in data.decode(errors="ignore"):
                    if byte in ("\r", "\n"):
                        channel.send(b"\r\n")
                        result = await self._handle_cmd(buf)
                        if result == "__EXIT__":
                            channel.send(b"logout\r\n")
                            break
                        if result:
                            channel.send(result.replace("\n", "\r\n").encode())
                        buf = ""
                        channel.send(self._prompt())
                    elif byte == "\x7f":
                        if buf:
                            buf = buf[:-1]
                            channel.send(b"\b \b")
                    elif byte == "\x03":
                        buf = ""
                        channel.send(b"^C\r\n")
                        channel.send(self._prompt())
                    else:
                        buf += byte
                        channel.send(byte.encode())
                else:
                    continue
                break
            except Exception:
                break

        return self.commands
