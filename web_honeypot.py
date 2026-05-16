import logging
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn

logger = logging.getLogger("web_honeypot")

FAKE_LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #1a1a2e; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: Arial; }
        .login-box { background: #16213e; padding: 40px; border-radius: 8px; width: 360px; box-shadow: 0 0 30px rgba(0,0,0,0.5); }
        h2 { color: #e94560; text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 8px 0; background: #0f3460; border: 1px solid #e94560; border-radius: 4px; color: white; }
        button { width: 100%; padding: 12px; background: #e94560; border: none; border-radius: 4px; color: white; cursor: pointer; font-size: 16px; margin-top: 10px; }
        .footer { color: #555; text-align: center; font-size: 11px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔒 Admin Panel</h2>
        <form method="POST" action="/admin/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="footer">Server Management Portal v2.4.1</div>
    </div>
</body>
</html>
"""

FAKE_ERROR_HTML = """
<!DOCTYPE html><html><body style="background:#1a1a2e;color:#e94560;font-family:Arial;text-align:center;padding-top:100px;">
<h2>❌ Invalid credentials. Please try again.</h2>
<a href="/admin" style="color:#aaa;">← Back to login</a>
</body></html>
"""

SQLI_PATTERNS = ["'", '"', "--", ";", "OR 1=1", "UNION", "SELECT", "DROP", "INSERT"]
XSS_PATTERNS = ["<script", "javascript:", "onerror", "onload", "alert("]


def detect_attack(value: str) -> str | None:
    v = value.upper()
    for p in SQLI_PATTERNS:
        if p.upper() in v:
            return "web_sqli"
    for p in XSS_PATTERNS:
        if p.upper() in v:
            return "web_xss"
    return None


def create_web_honeypot(alert_manager) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None)

    @app.get("/admin", response_class=HTMLResponse)
    @app.get("/admin/", response_class=HTMLResponse)
    @app.get("/wp-admin", response_class=HTMLResponse)
    @app.get("/phpmyadmin", response_class=HTMLResponse)
    @app.get("/login", response_class=HTMLResponse)
    async def admin_page(request: Request):
        ip = request.client.host
        event = {"event_type": "web_admin", "ip": ip, "port": 8080,
                 "payload": str(request.url), "severity": "medium"}
        await alert_manager.trigger(event)
        return HTMLResponse(FAKE_LOGIN_HTML)

    @app.post("/admin/login", response_class=HTMLResponse)
    async def admin_login(request: Request, username: str = Form(""), password: str = Form("")):
        ip = request.client.host
        attack_type = detect_attack(username) or detect_attack(password) or "web_login"
        severity = "high" if attack_type in ("web_sqli", "web_xss") else "medium"
        event = {"event_type": attack_type, "ip": ip, "port": 8080,
                 "username": username, "password": password, "severity": severity}
        await alert_manager.trigger(event)
        return HTMLResponse(FAKE_ERROR_HTML)

    @app.get("/{path:path}")
    async def catch_all(request: Request, path: str):
        ip = request.client.host
        suspicious = any(p in path.lower() for p in [".php", ".env", "config", "backup", "shell", "cmd"])
        if suspicious:
            event = {"event_type": "web_scan", "ip": ip, "port": 8080,
                     "payload": f"GET /{path}", "severity": "low"}
            await alert_manager.trigger(event)
        return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)

    return app


async def start_web_honeypot(host: str, port: int, alert_manager):
    app = create_web_honeypot(alert_manager)
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    await server.serve()
