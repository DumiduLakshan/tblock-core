from pathlib import Path
import os
import sys
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ban_store import BanStore
from torrent_watch import Settings, load_settings, XuiClient

security = HTTPBasic()

app = FastAPI(title="tblock.fk bans")
SETTINGS: Optional[Settings] = None
STORE: Optional[BanStore] = None
XUI: Optional[XuiClient] = None


def init():
    global SETTINGS, STORE, XUI
    load_dotenv()
    SETTINGS = load_settings()
    STORE = BanStore(SETTINGS.ban_db)
    XUI = XuiClient(SETTINGS)


def auth(creds: HTTPBasicCredentials = Depends(security)) -> None:
    if not SETTINGS:
        raise HTTPException(status_code=500, detail="Not ready")
    user_ok = creds.username == SETTINGS.username
    pass_ok = creds.password == SETTINGS.password
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/", response_class=HTMLResponse)
def home(q: str = "", _: None = Depends(auth)):
    bans = STORE.list(q) if STORE else []
    stats = STORE.stats() if STORE else {"total": 0}
    rows = "".join(
        f"<tr><td>{b['email']}</td><td>{b['ip']}</td><td>{b['domain']}</td><td>{b['created_at']}</td>"
        f"<td><form method='post' action='/unban'>"
        f"<input type='hidden' name='email' value='{b['email']}'/>"
        f"<button type='submit' class='pill red'>Unban</button></form></td></tr>"
        for b in bans
    )
    html = f"""
    <html><head><title>tblock.fk bans</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <style>
    :root {{
      --bg: #f9fafb;
      --card: #ffffff;
      --border: #e5e7eb;
      --text: #0f172a;
      --muted: #6b7280;
      --accent: #2563eb;
      --accent2: #22d3ee;
      --danger: #ef4444;
      --radius: 14px;
      --shadow: 0 20px 60px rgba(15,23,42,0.08);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }}
    body {{ margin:0; padding:18px; background: var(--bg); color: var(--text); }}
    .hero {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }}
    .title {{ font-size:24px; font-weight:700; letter-spacing:-0.5px; }}
    .credit {{ color: var(--muted); font-size:12px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin:12px 0; }}
    .card {{ background: var(--card); border:1px solid var(--border); border-radius: var(--radius); padding:14px; box-shadow: var(--shadow); }}
    table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
    th,td {{ padding:10px 8px; border-bottom:1px solid var(--border); font-size:13px; }}
    th {{ text-align:left; color: var(--muted); }}
    input {{ width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:10px; }}
    .pill {{ padding:8px 12px; border:none; border-radius:10px; color:#fff; background: linear-gradient(135deg, var(--accent), var(--accent2)); cursor:pointer; }}
    .pill.red {{ background: linear-gradient(135deg, #ef4444, #f97316); }}
    .pill.subtle {{ background:#f3f4f6; color:#111827; border:1px solid var(--border); }}
    @media (max-width: 640px) {{ th,td {{ font-size:12px; }} }}
    </style></head><body>
    <div class="hero">
      <div><div class="title">tblock.fk ban manager</div><div class="credit">built by @dragonforce</div></div>
      <div class="card" style="padding:10px 12px;">Total bans: {stats['total']}</div>
    </div>
    <div class="grid">
      <div class="card">
        <form method="get">
          <div style="display:flex; gap:8px; align-items:center;">
            <input name="q" placeholder="Search email" value="{q}" />
            <button class="pill subtle" type="submit">Search</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card" style="overflow-x:auto;">
      <table>
        <thead><tr><th>Email</th><th>IP</th><th>Domain</th><th>When</th><th>Action</th></tr></thead>
        <tbody>{rows or '<tr><td colspan="5" style="color:var(--muted)">No bans yet.</td></tr>'}</tbody>
      </table>
    </div>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.post("/unban")
def unban(email: str = Form(...), _: None = Depends(auth)):
    if not XUI or not STORE:
        raise HTTPException(status_code=500, detail="Not ready")
    client = XUI.get_client(email)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
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


init()

if __name__ == "__main__":
    port = int(os.getenv("PANEL_PORT", "2374"))
    uvicorn.run("panel_app:app", host="0.0.0.0", port=port, reload=False)
