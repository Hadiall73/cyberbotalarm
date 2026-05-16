import json
import logging
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn
from core.database import get_events, get_stats, get_attackers, get_sessions

logger = logging.getLogger("dashboard")
TEMPLATE = (Path(__file__).parent / "templates" / "index.html").read_text(encoding="utf-8")


def create_app(alert_manager) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(TEMPLATE)

    @app.get("/api/stats")
    async def stats():
        return get_stats()

    @app.get("/api/events")
    async def events():
        return get_events(200)

    @app.get("/api/attackers")
    async def attackers():
        return get_attackers(50)

    @app.get("/api/sessions")
    async def sessions():
        return get_sessions(50)

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        alert_manager.register_ws(websocket)
        try:
            history = get_events(100)
            await websocket.send_text(json.dumps({"type": "history", "events": history}))
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            alert_manager.unregister_ws(websocket)

    return app


async def start(host: str, port: int, alert_manager):
    app = create_app(alert_manager)
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    await server.serve()
