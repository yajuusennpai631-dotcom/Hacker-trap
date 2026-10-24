import json
import logging
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

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
    # Never parse or store submitted form fields, request bodies, or passwords.
    path = request.url.path[:300]
    query_keys = sorted({key[:80] for key in request.query_params.keys()})[:30]
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
    # Public dashboard receives event metadata only, never IPs, user agents,
    # query values, request bodies, or credentials.
    if DASHBOARD_INGEST_URL and INGEST_TOKEN:
        public_event = {
            "timestamp": payload["timestamp"],
            "event": event,
            "method": payload["method"],
            "path": path,
            "status_code": status_code,
            "tags": tags,
            # Sent only to the private ingest endpoint for coarse geolocation;
            # the dashboard resolves it and discards the raw IP.
            "client_ip": (
                request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                or (request.client.host if request.client else None)
            ),
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


CAMERA_PAGE = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HomeNest Cam - カメラ設定</title>
<style>
:root{--blue:#2878c8;--line:#d9e0e7;--ink:#283746;--muted:#73808c}
*{box-sizing:border-box}body{margin:0;background:#eef2f5;color:var(--ink);font:14px Arial,"Noto Sans JP",sans-serif}
header{background:#fff;border-bottom:1px solid var(--line);padding:13px max(18px,calc((100% - 1000px)/2));display:flex;align-items:center;justify-content:space-between}
.brand{font-size:20px;font-weight:700;color:#315b7d}.brand span{color:var(--blue)}
header small{color:var(--muted)}main{max-width:1000px;margin:24px auto;padding:0 16px}
h1{font-size:21px;font-weight:500;margin:0 0 5px}.sub{color:var(--muted);margin:0 0 18px}
.grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(240px,1fr);gap:16px}
.card{background:white;border:1px solid var(--line);border-radius:5px;padding:17px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 14px;border-bottom:1px solid #edf0f2;padding-bottom:11px}
.preview{height:270px;background:linear-gradient(180deg,#b8c4c9 0%,#d8d7ca 60%,#a9b4ad 60%,#8b9a91 100%);position:relative;overflow:hidden;border:1px solid #aab4bb}
.preview:before{content:"";position:absolute;left:12%;right:12%;bottom:0;height:46%;background:repeating-linear-gradient(90deg,#8b9690 0 2px,transparent 2px 80px);border-top:3px solid #7e8d84}
.preview:after{content:"";position:absolute;width:80px;height:80px;border-radius:50%;background:#e5e7e2;left:calc(50% - 40px);top:55px;box-shadow:0 0 0 14px #a9b5b9,0 0 0 17px #77858b}
.overlay{position:absolute;z-index:2;top:10px;left:10px;background:#202b31c9;color:white;padding:6px 8px;font-size:12px}
.offline{position:absolute;z-index:3;inset:0;display:grid;place-items:center;background:#25313a35;color:#fff;text-shadow:0 1px 4px #333;font-size:17px;font-weight:bold}
.row{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #eef1f3}.row:last-child{border:0}
.good{color:#9a6b20}.btn{display:inline-block;padding:9px 13px;background:var(--blue);color:#fff;text-decoration:none;border-radius:3px;border:0;cursor:pointer}
.links{display:flex;gap:9px;flex-wrap:wrap;margin-top:13px}.links a{color:#2769a3}
label{display:block;margin:12px 0 5px}input{width:100%;padding:10px;border:1px solid #cbd4dc;border-radius:3px}
footer{max-width:1000px;margin:10px auto 25px;padding:0 16px;color:#7b8790;font-size:11px}
@media(max-width:680px){.grid{grid-template-columns:1fr}.preview{height:220px}header{padding:13px 16px}}
</style></head><body>
<header><div class="brand">HomeNest <span>Cam</span></div><small>家庭用ネットワークカメラ</small></header>
<main><h1>カメラ管理画面</h1><p class="sub">デバイス情報とネットワーク設定を確認できます。</p>
<div class="grid"><section>
<div class="card"><h2>ライブ映像</h2>
<div class="preview"><div class="overlay">CAM-01　|　プレビュー</div><div class="offline">映像を読み込めません</div></div>
<div class="row"><span>映像ステータス</span><b class="good">接続待ち</b></div>
<div class="row"><span>最終更新</span><span>--:--:--</span></div>
<p style="color:#73808c;font-size:12px">ネットワーク接続を確認してください。</p></div>
<div class="card"><h2>デバイス情報</h2>
<div class="row"><span>デバイス名</span><span>LivingRoom-Cam</span></div>
<div class="row"><span>モデル</span><span>HN-C100</span></div>
<div class="row"><span>ファームウェア</span><span>1.0.8</span></div>
<div class="row"><span>ネットワーク</span><span>LAN / DHCP</span></div></div>
</section><aside>
<div class="card"><h2>カメラの状態</h2>
<div class="row"><span>電源</span><b>オン</b></div><div class="row"><span>ネットワーク</span><b class="good">未確認</b></div>
<div class="row"><span>ストレージ</span><b>未設定</b></div><div class="row"><span>時刻同期</span><b>未設定</b></div>
</div>
<div class="card"><h2>管理メニュー</h2>
<p>設定を変更するには管理者としてログインしてください。</p>
<a class="btn" href="/login">管理者ログイン</a>
<div class="links"><a href="/config">ネットワーク設定</a><a href="/admin">詳細設定</a><a href="/api/status">端末情報</a></div>
</div>
<div class="card"><h2>お知らせ</h2><p>初回設定が完了していません。管理者ページから設定を確認してください。</p></div>
</aside></div></main>
<footer>HomeNest Cam HN-C100 ・ 調査用の架空デバイス画面です。実際のカメラ映像や機器には接続していません。</footer>
</body></html>"""


def simple_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} - HomeNest Cam</title>
<style>body{{font:14px Arial,sans-serif;background:#eef2f5;color:#283746;margin:0;padding:24px}}
main{{max-width:540px;margin:30px auto;background:#fff;border:1px solid #d9e0e7;padding:24px;border-radius:5px}}
h1{{font-size:21px;font-weight:500}}label{{display:block;margin:14px 0 5px}}
input{{box-sizing:border-box;width:100%;padding:10px;border:1px solid #cbd4dc}}
button{{margin-top:15px;background:#2878c8;color:white;border:0;padding:10px 14px;cursor:pointer}}
a{{color:#2769a3}}small{{color:#73808c}}</style></head><body><main><h1>{title}</h1>{body}
<p><a href="/">カメラ画面に戻る</a></p></main></body></html>""")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(CAMERA_PAGE)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return simple_page("管理者ログイン", """
<p>カメラの設定を変更するにはログインしてください。</p>
<form method="post" action="/login">
<label>ユーザー名</label><input name="username" autocomplete="off">
<label>パスワード</label><input type="password" name="password" autocomplete="off">
<button type="submit">ログイン</button></form>
<small>ログインできない場合はネットワーク接続を確認してください。</small>""")


@app.post("/login", response_class=HTMLResponse)
async def fake_login(request: Request):
    # Deliberately do not parse the form: submitted credentials are never stored.
    await record_event(request, "login_attempt", 200)
    return simple_page("ログインできません", """
<p>ユーザー情報を確認できませんでした。</p>
<p>時間をおいて再度お試しください。</p>""")


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    await record_event(request, "admin_page_access", 200)
    return simple_page("詳細設定", """
<div class="row">管理者アカウント <b>未設定</b></div>
<div class="row">リモートアクセス <b>無効</b></div>
<div class="row">ファームウェア更新 <b>確認が必要</b></div>
<p><a href="/config">ネットワーク設定を開く</a></p>""")


@app.get("/dashboard", response_class=HTMLResponse)
async def device_dashboard():
    return await home()


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    await record_event(request, "config_page_access", 200)
    return simple_page("ネットワーク設定", """
<form><label>接続方式</label><input value="DHCP" readonly>
<label>デバイス名</label><input value="LivingRoom-Cam" readonly>
<label>接続状態</label><input value="未確認" readonly>
<button type="button" onclick="location.href='/login'">管理者ログイン</button></form>""")


@app.get("/wp-login.php", response_class=HTMLResponse)
async def generic_login_decoy():
    return await login_page()


@app.get("/fake-shell", response_class=HTMLResponse)
async def fake_shell(request: Request):
    # Visual-only decoy; never launches a shell or executes submitted commands.
    await record_event(request, "fake_shell_access", 200)
    return HTMLResponse("""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance Console</title>
<style>body{background:#080d18;color:#b7f7d2;font:15px ui-monospace,monospace;padding:28px}
main{max-width:760px;margin:auto;border:1px solid #285642;border-radius:10px;padding:22px;background:#0c1718}
h1{font-size:19px;color:#65e6a4}.tag{color:#f4ca75}pre{white-space:pre-wrap;line-height:1.7}</style></head>
<body><main><h1>Maintenance Console</h1><div class="tag">SIMULATED ENVIRONMENT · READ ONLY</div>
<pre>Session: restricted
Environment: decoy
Command execution: disabled
Filesystem access: disabled
Audit: access event recorded

This endpoint is a non-functional honeypot decoy.
No operating-system shell is available.</pre></main></body></html>""")


@app.get("/api/status")
async def fake_api_status():
    return JSONResponse({"status": "ok", "version": "1.0", "device": "HN-C100"})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def catch_all(request: Request, path: str):
    # Metadata only; uploaded files and submitted commands are never executed.
    return PlainTextResponse("Not Found", status_code=404)
