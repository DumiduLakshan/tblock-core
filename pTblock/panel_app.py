import os
import sys
import secrets
import hmac
import hashlib
from typing import Optional
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from dotenv import load_dotenv
import requests

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ban_store import BanStore
from torrent_watch import Settings, load_settings, XuiClient

app = FastAPI(title="Tblock Admin")
SETTINGS: Optional[Settings] = None
STORE: Optional[BanStore] = None
XUI: Optional[XuiClient] = None
SECRET: str = secrets.token_hex(16)


def init():
    global SETTINGS, STORE, XUI, SECRET
    load_dotenv()
    SETTINGS = load_settings()
    STORE = BanStore(SETTINGS.ban_db)
    XUI = XuiClient(SETTINGS)
    SECRET = hashlib.sha256(f"{SETTINGS.username}{SETTINGS.password}".encode()).hexdigest()


def sign_cookie(username: str) -> str:
    msg = username.encode()
    sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()
    return f"{username}:{sig}"


def verify_cookie(token: str) -> bool:
    if ":" not in token:
        return False
    user, sig = token.split(":", 1)
    expected = hmac.new(SECRET.encode(), user.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected) and user == SETTINGS.username


def require_auth(request: Request):
    if not SETTINGS:
        raise HTTPException(status_code=500, detail="Not ready")
    token = request.cookies.get("tblock_auth", "")
    if not token or not verify_cookie(token):
        raise HTTPException(status_code=401, detail="Unauthorized")


def fetch_token_info(ip: str) -> Optional[dict]:
    if not SETTINGS:
        return None
    validator_url = SETTINGS.validator_url or os.getenv("VALIDATOR_URL", "").rstrip("/")
    if not validator_url:
        return None
    try:
        res = requests.post(
            f"{validator_url}/token-by-ip",
            json={"vps_ip": ip},
            timeout=8,
            verify=False,
        )
        if res.status_code == 200:
            return res.json()
    except Exception:
        return None
    return None


@app.get("/login", response_class=HTMLResponse)
def login_page():
    html = """
    <html><head><title>Tblock Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
    body { margin:0; display:flex; align-items:center; justify-content:center; min-height:100vh; background:#f2f4ff;
           font-family:'Poppins',sans-serif; }
    .card { background:#fff; padding:26px; border-radius:16px; box-shadow:0 24px 70px rgba(79,70,229,0.18);
            width: min(420px, 94%); }
    h2 { margin:0 0 18px 0; text-align:center; color:#111827; letter-spacing:-0.4px; }
    label { display:block; margin-bottom:6px; color:#6b7280; font-size:13px; }
    input { width:100%; padding:12px; border-radius:10px; border:1px solid #e5e7eb; font-size:14px; }
    button { width:100%; padding:12px; border:none; border-radius:10px; margin-top:14px;
             background:linear-gradient(135deg,#6366f1,#7c3aed); color:#fff; font-weight:600; cursor:pointer;
             box-shadow:0 16px 40px rgba(99,102,241,0.28); }
    .credit { text-align:center; margin-top:10px; color:#9ca3af; font-size:12px; }
    </style></head><body>
    <div class="card">
      <h2>Tblock Admin</h2>
      <form method="post" action="/login">
        <label>Username</label>
        <input name="username" required />
        <label style="margin-top:10px;">Password</label>
        <input name="password" type="password" required />
        <button type="submit">Sign in</button>
      </form>
      <div class="credit">crafted by @dragonforce</div>
    </div>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    if not SETTINGS:
        raise HTTPException(status_code=500, detail="Not ready")
    if username == SETTINGS.username and password == SETTINGS.password:
        token = sign_cookie(username)
        resp = RedirectResponse(url="/", status_code=302)
        resp.set_cookie("tblock_auth", token, httponly=True, max_age=60 * 60 * 12)
        return resp
    return HTMLResponse("<html><body>Invalid credentials.<br><a href='/login'>Try again</a></body></html>", status_code=401)


@app.get("/", response_class=HTMLResponse)
def home(q: str = "", request: Request = None):
    try:
        require_auth(request)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)
    bans = STORE.list(q) if STORE else []
    enriched = []
    for b in bans:
        info = fetch_token_info(b["ip"])
        enriched.append({**b, "token_info": info})
    current_token = fetch_token_info(os.getenv("VPS_IP", "")) if SETTINGS else None
    token_val = current_token.get("token") if current_token else "—"
    expires_in = current_token.get("expires_in_seconds") if current_token else None
    if expires_in is not None:
        mins_left = max(int(expires_in // 60), 0)
        token_exp_str = f"expires in {mins_left} min"
    else:
        token_exp_str = "expiry unknown"
    stats = STORE.stats() if STORE else {"total": 0}
    rows = ""
    for b in enriched:
        info = b.get("token_info") or {}
        expires_in = info.get("expires_in_seconds")
        expires_str = ""
        if expires_in is not None:
            mins = max(int(expires_in // 60), 0)
            expires_str = f"{mins} min"
        token_badge = info.get("token") or "—"
        username = info.get("username") or ""
        rows += (
            f"<tr onclick=\"showDetails('{b['email']}')\" style='cursor:pointer;'>"
            f"<td>{b['email']}</td><td>{b['ip']}</td><td>{b['domain']}</td><td>{b['created_at']}</td>"
            f"<td>{username}</td><td>{token_badge}<br/><span style='color:#ef4444;font-size:12px;'>{expires_str}</span></td>"
            f"<td><form method='post' action='/unban' onClick='event.stopPropagation();'>"
            f"<input type='hidden' name='email' value='{b['email']}'/>"
            f"<button type='submit' class='pill red'>Unban</button></form></td></tr>"
        )
    html = f"""
    <html><head><title>Tblock Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
    :root {{
      --bg: #f4f6fb;
      --card: #ffffff;
      --border: #e5e7eb;
      --text: #0f172a;
      --muted: #6b7280;
      --accent: #6366f1;
      --accent2: #7c3aed;
      --danger: #ef4444;
      --radius: 16px;
      --shadow: 0 24px 70px rgba(99,102,241,0.08);
      font-family: 'Poppins', system-ui, -apple-system, sans-serif;
    }}
    body {{ margin:0; padding:18px; background: var(--bg); color: var(--text); }}
    .hero {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }}
    .title {{ font-size:24px; font-weight:700; letter-spacing:-0.5px; }}
    .credit {{ color: var(--muted); font-size:12px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin:12px 0; }}
    .card {{ background: var(--card); border:1px solid var(--border); border-radius: var(--radius); padding:14px; box-shadow: var(--shadow); }}
    table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
    th,td {{ padding:12px 10px; border-bottom:1px solid var(--border); font-size:13px; }}
    th {{ text-align:left; color: var(--muted); }}
    input {{ width:100%; padding:12px; border:1px solid var(--border); border-radius:12px; }}
    .pill {{ padding:10px 12px; border:none; border-radius:12px; color:#fff; background: linear-gradient(135deg, var(--accent), var(--accent2)); cursor:pointer; box-shadow:0 16px 40px rgba(99,102,241,0.18); }}
    .pill.red {{ background: linear-gradient(135deg, #ef4444, #f97316); }}
    .pill.subtle {{ background:#f3f4f6; color:#111827; border:1px solid var(--border); box-shadow:none; }}
    .modal-backdrop {{
      position:fixed; inset:0; background:rgba(15,23,42,0.45); display:none; align-items:center; justify-content:center; padding:12px;
    }}
    .modal {{
      background:#fff; border-radius:16px; padding:16px; max-width:400px; width:100%; box-shadow:0 30px 80px rgba(0,0,0,0.2);
      border:1px solid #e5e7eb;
    }}
    @media (max-width: 640px) {{ th,td {{ font-size:12px; }} .hero {{ align-items:flex-start; gap:4px; }} }}
    </style></head><body>
    <div class="hero">
      <div><div class="title">Tblock Admin</div><div class="credit">crafted by @dragonforce</div></div>
      <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
        <div class="card" style="padding:10px 12px; display:flex; gap:12px;">Total bans: {stats['total']}</div>
        <div class="card" style="padding:10px 12px; display:flex; gap:10px; align-items:center;">
          <div style="font-weight:600;">This VPS token</div>
          <div style="font-family:monospace;">{token_val}</div>
          <div style="color:#ef4444; font-size:12px;">{token_exp_str}</div>
        </div>
      </div>
    </div>
    <div class="grid">
      <div class="card">
        <form method="get">
          <div style="display:flex; gap:8px; align-items:center;">
            <input name="q" placeholder="Search email" value="{q}" />
            <button class="pill subtle" type="submit" style="width:120px;">Search</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table>
        <thead><tr><th>Email</th><th>IP</th><th>Domain</th><th>When</th><th>User</th><th>Token/Expiry</th><th>Action</th></tr></thead>
        <tbody>{rows or '<tr><td colspan="5" style="color:var(--muted)">No bans yet.</td></tr>'}</tbody>
      </table>
    </div>
    <div id="modal" class="modal-backdrop" onclick="hideModal()">
      <div class="modal" onclick="event.stopPropagation();">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:700;">Client details</div>
          <button class="pill subtle" style="width:80px;" onclick="hideModal()">Close</button>
        </div>
        <div id="modal-body" style="margin-top:10px;color:#111827;font-size:14px;"></div>
      </div>
    </div>
    <script>
    async function showDetails(email) {{
      try {{
        const res = await fetch(`/api/client/${{encodeURIComponent(email)}}`);
        if (!res.ok) throw new Error('Request failed');
        const data = await res.json();
        const body = document.getElementById('modal-body');
        body.innerHTML = `
          <div><strong>Email:</strong> ${'{'}data.email || email{'}'}</div>
          <div><strong>Inbound ID:</strong> ${'{'}data.inboundId || '-'{' }'}</div>
          <div><strong>UUID:</strong> ${'{'}data.uuid || '-'{' }'}</div>
          <div><strong>Status:</strong> ${'{'}data.enable ? 'Enabled' : 'Disabled'{'}'}</div>
          <div><strong>Up/Down/Total:</strong> ${'{'}data.up || '-'{' }'} / ${'{'}data.down || '-'{' }'} / ${'{'}data.total || '-'{' }'}</div>
          <div><strong>Sub ID:</strong> ${'{'}data.subId || '-'{' }'}</div>
          <div><strong>All Time:</strong> ${'{'}data.allTime || '-'{' }'}</div>
          <div><strong>Expiry:</strong> ${'{'}data.expiryTime || '-'{' }'}</div>
          <div><strong>Reset:</strong> ${'{'}data.reset || '-'{' }'}</div>
          <div><strong>Last Online:</strong> ${'{'}data.lastOnline || '-'{' }'}</div>
        `;
        document.getElementById('modal').style.display = 'flex';
      }} catch (err) {{
        const body = document.getElementById('modal-body');
        body.innerHTML = `<div style="color:#ef4444;">Failed to load details.</div>`;
        document.getElementById('modal').style.display = 'flex';
      }}
    }}
    function hideModal() {{
      document.getElementById('modal').style.display = 'none';
    }}
    </script>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.post("/unban")
def unban(email: str = Form(...), request: Request = None):
    try:
        require_auth(request)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)
    if not XUI or not STORE:
        raise HTTPException(status_code=500, detail="Not ready")
    client = XUI.get_client(email)
    if not client:
        STORE.mark_unbanned(email)
        return RedirectResponse(url="/", status_code=302)
    inbound_id = client.get("inboundId") or client.get("inbound_id")
    client_uuid = client.get("uuid") or client.get("id")
    if inbound_id is None or client_uuid is None:
        raise HTTPException(status_code=400, detail="Client data incomplete")
    try:
        XUI.set_client_enabled(inbound_id, client_uuid, True)
        STORE.mark_unbanned(email)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return RedirectResponse(url="/", status_code=302)


@app.get("/api/client/{email}")
def client_details(email: str, request: Request = None):
    try:
        require_auth(request)
    except Exception:
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    try:
        client = XUI.get_client(email)
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=500)
    if not client:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    up = client.get("up", 0)
    down = client.get("down", 0)
    total = client.get("total", 0)

    def bytes_to_human(num: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num < 1024:
                return f"{num:.2f} {unit}"
            num /= 1024
        return f"{num:.2f} PB"

    resp = {
        "email": client.get("email"),
        "inboundId": client.get("inboundId") or client.get("inbound_id"),
        "uuid": client.get("uuid") or client.get("id"),
        "enable": client.get("enable"),
        "up": bytes_to_human(int(up)),
        "down": bytes_to_human(int(down)),
        "total": bytes_to_human(int(total)),
        "subId": client.get("subId") or client.get("subid"),
        "allTime": bytes_to_human(int(client.get("allTime", 0))),
        "expiryTime": client.get("expiryTime"),
        "reset": client.get("reset"),
        "lastOnline": client.get("lastOnline"),
    }
    return JSONResponse(resp)


init()

if __name__ == "__main__":
    port = int(os.getenv("PANEL_PORT", "2374"))
    uvicorn.run("panel_app:app", host="0.0.0.0", port=port, reload=False)
