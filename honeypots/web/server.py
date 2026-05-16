import logging
from pathlib import Path
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from core.ip_intel import detect_tool
from core.honeytokens import check_token
import uvicorn

logger = logging.getLogger("web_honeypot")

TEMPLATES = Path(__file__).parent / "templates"
STATIC    = Path(__file__).parent / "static"

SQLI = ["'","\"","--",";","OR 1=1","UNION SELECT","DROP TABLE","INSERT INTO","1=1","' OR","1' OR"]
XSS  = ["<script","javascript:","onerror=","onload=","alert(","document.cookie","eval("]
RCE  = ["|bash","| sh","| python","; cat ","; wget ","$(","${","&&wget","&&curl","/etc/passwd","../.."]
TRAV = ["../","..%2f","..%5c","%2e%2e"]

def _classify(val: str) -> str | None:
    v = val.lower()
    for p in RCE:
        if p.lower() in v: return "web_rce_attempt"
    for p in SQLI:
        if p.lower() in v: return "web_sqli"
    for p in XSS:
        if p.lower() in v: return "web_xss"
    for p in TRAV:
        if p.lower() in v: return "web_path_traversal"
    return None

def _load(name: str, **kwargs) -> str:
    tpl = (TEMPLATES / name).read_text(encoding="utf-8")
    for k, v in kwargs.items():
        tpl = tpl.replace("{{" + k + "}}", v)
    return tpl

def create_app(alert_manager, tokens: dict) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/fp", StaticFiles(directory=str(STATIC)), name="fp")

    # ── Fingerprint collector ──────────────────────────────────────────
    @app.post("/fp/collect")
    async def fp_collect(request: Request):
        ip = request.client.host
        data = await request.json()
        real_ips = data.get("webrtcIPs", [])
        fp = {
            "userAgent":    data.get("userAgent",""),
            "screen":       data.get("screen",""),
            "timezone":     data.get("timezone",""),
            "language":     data.get("language",""),
            "platform":     data.get("platform",""),
            "canvas":       data.get("canvasFingerprint",""),
            "webgl":        data.get("webglRenderer",""),
            "fonts":        data.get("fonts",[]),
            "audio":        data.get("audioFingerprint",""),
            "plugins":      data.get("plugins",[]),
            "hardware":     data.get("hardwareConcurrency",""),
            "memory":       data.get("deviceMemory",""),
        }
        from core import database as db
        db.upsert_attacker(ip, fingerprint=fp, real_ips=real_ips)
        tools = detect_tool(user_agent=fp.get("userAgent",""))
        if tools:
            db.upsert_attacker(ip, tools=tools)
        if real_ips:
            await alert_manager.trigger("web_fingerprint", ip, 8080, {
                "real_ips": real_ips,
                "fingerprint": fp,
                "webrtc_leak": len(real_ips) > 0,
            }, force=True)
        return JSONResponse({"ok": True})

    # ── Admin login page ───────────────────────────────────────────────
    @app.get("/admin", response_class=HTMLResponse)
    @app.get("/admin/", response_class=HTMLResponse)
    @app.get("/wp-admin", response_class=HTMLResponse)
    @app.get("/wp-admin/", response_class=HTMLResponse)
    @app.get("/login", response_class=HTMLResponse)
    @app.get("/administrator", response_class=HTMLResponse)
    @app.get("/phpmyadmin", response_class=HTMLResponse)
    @app.get("/panel", response_class=HTMLResponse)
    async def admin_get(request: Request):
        ip = request.client.host
        ua = request.headers.get("user-agent","")
        tools = detect_tool(user_agent=ua)
        await alert_manager.trigger("web_admin_access", ip, 8080, {
            "path": str(request.url.path),
            "user_agent": ua,
            "tools_detected": tools,
        })
        html = _load("admin.html", alert_display="none", alert_msg="")
        return HTMLResponse(html)

    @app.post("/admin/login", response_class=HTMLResponse)
    async def admin_post(request: Request, username: str = Form(""), password: str = Form("")):
        ip = request.client.host
        attack = _classify(username) or _classify(password)
        honeytoken_label = check_token(username, ip) or check_token(password, ip)

        if honeytoken_label:
            await alert_manager.trigger("honeytoken_triggered", ip, 8080, {
                "label": honeytoken_label, "username": username
            }, force=True)

        event_type = attack or "web_login_attempt"
        await alert_manager.trigger(event_type, ip, 8080, {
            "username": username,
            "password": password,
        })

        # Lass ihn "rein" — zeige fake Dashboard
        html = _load("dashboard_fake.html")
        return HTMLResponse(html)

    @app.get("/admin/logout")
    async def admin_logout():
        return RedirectResponse("/admin")

    # ── Fake config/backup files als Honeytokens ───────────────────────
    @app.get("/.env")
    @app.get("/config.php")
    @app.get("/wp-config.php")
    @app.get("/backup.sql")
    async def fake_files(request: Request):
        ip = request.client.host
        path = request.url.path
        await alert_manager.trigger("web_sensitive_file", ip, 8080, {
            "path": path, "severity": "high"
        }, force=True)
        from core.honeytokens import get_fake_env_file
        return HTMLResponse(get_fake_env_file(tokens), media_type="text/plain")

    # ── Catch-all für Scanner ──────────────────────────────────────────
    @app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE","HEAD","OPTIONS"])
    async def catch_all(request: Request, path: str):
        ip = request.client.host
        ua = request.headers.get("user-agent","")
        body = ""
        try:
            body = (await request.body()).decode(errors="ignore")[:500]
        except Exception:
            pass

        full = path + body
        attack = _classify(full) or _classify(ua)
        tools  = detect_tool(user_agent=ua, payload=full)
        honeytoken_label = check_token(body, ip)

        if honeytoken_label:
            await alert_manager.trigger("honeytoken_triggered", ip, 8080, {
                "label": honeytoken_label
            }, force=True)

        if attack or tools:
            await alert_manager.trigger(attack or "web_scan", ip, 8080, {
                "path": "/" + path,
                "user_agent": ua,
                "payload": body[:200],
                "tools_detected": tools,
            })
        elif path:
            await alert_manager.trigger("web_scan", ip, 8080, {
                "path": "/" + path,
                "user_agent": ua,
            })

        return HTMLResponse("<html><body><h1>404 Not Found</h1></body></html>", status_code=404)

    return app


async def start(host: str, port: int, alert_manager, tokens: dict):
    app = create_app(alert_manager, tokens)
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    await server.serve()
