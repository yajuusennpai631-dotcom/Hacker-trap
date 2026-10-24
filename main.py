import json
import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("honeypot")
DASHBOARD_INGEST_URL = os.environ.get("DASHBOARD_INGEST_URL", "")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")

app = FastAPI(title="Hacker Trap", docs_url=None, redoc_url=None, openapi_url=None)

SUSPICIOUS_MARKERS = (
    "wp-login", "wp-admin", ".env", "phpmyadmin", "admin",
    "passwd", "proc/self", "etc/passwd", "union select",
    " or 1=1", "../", "..%2f", "<script", "cmd=",
)


async def record_event(request: Request, event: str, status_code: int = 200) -> None:
    # Deliberately do not read request bodies or record form values/passwords.
    path = request.url.path[:300]
    query_keys = sorted({key[:80] for key in request.query_params.keys()})[:30
    ]
    haystack = (path + " " + str(request.url.query)).lower()
    tags = [marker for marker in SUSPICIOUS_MARKERS if marker in haystack]
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "method": request.method,
        "path": path,
        "query_keys": query_keys,
        "client_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:300],
        "status_code": status_code,
        "tags": tags,
    }
    logger.info(json.dumps(payload, ensure_ascii=False))
    # Send only non-identifying event metadata to the public dashboard.
    # IP, user-agent, query values, request bodies, and credentials are excluded.
    if DASHBOARD_INGEST_URL and INGEST_TOKEN:
        public_event = {
            "timestamp": payload["timestamp"],
            "event": event,
            "method": payload["method"],
            "path": path,
            "status_code": status_code,
            "tags": tags,
        }
        try:
            async with httpx.AsyncClient(timeout=1.2) as client:
                await client.post(
                    DASHBOARD_INGEST_URL,
                    json=public_event,
                    headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
                )
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "dashboard_delivery_failed",
                "reason": type(exc).__name__,
            }))


@app.middleware("http")
async def log_requests(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        await record_event(request, "server_error", 500)
        raise
    await record_event(request, "http_request", response.status_code)
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse("""
    <!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Control Panel</title>
    <style>
      body{font-family:system-ui,sans-serif;background:#101827;color:#e5e7eb;
      display:grid;place-items:center;min-height:100vh;margin:0}
      main{width:min(360px,85vw);background:#1f2937;padding:2rem;border-radius:12px}
      input,button{box-sizing:border-box;width:100%;padding:.8rem;margin:.4rem 0;
      border-radius:6px;border:1px solid #4b5563}
      button{background:#2563eb;color:white;border:0;cursor:pointer}
      small{color:#9ca3af}
    </style></head><body><main><h1>Control Panel</h1>
    <p>Sign in to continue.</p>
    <form method="post" action="/login">
      <label>Username<input name="username" autocomplete="off"></label>
      <label>Password<input type="password" name="password" autocomplete="off"></label>
      <button type="submit">Sign in</button>
    </form><small>Authorized personnel only.</small></main></body></html>
    """)


@app.post("/login", response_class=HTMLResponse)
async def fake_login(request: Request):
    # No submitted credentials are parsed, logged, or persisted.
    await record_event(request, "login_attempt", 200)
    return HTMLResponse(
        "<h1>Sign-in failed</h1><p>Unable to verify credentials.</p>",
        status_code=200,
    )


@app.get("/admin", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/wp-login.php", response_class=HTMLResponse)
async def decoy_pages(request: Request):
    return await home()


@app.get("/api/status")
async def fake_api_status():
    return JSONResponse({"status": "ok", "version": "1.0"})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def catch_all(request: Request, path: str):
    # Record only request metadata; never execute uploaded files or submitted commands.
    return PlainTextResponse("Not Found", status_code=404)
