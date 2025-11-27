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
    stats = STORE.stats() if STORE else {"total": 0, "unbanned": 0, "banned": 0}
    rows = "".join(
        f"<tr><td>{b['email']}</td><td>{b['ip']}</td><td>{b['domain']}</td><td>{b['status']}</td>"
        f"<td>{b['created_at']}</td><td><form method='post' action='/unban'>"
        f"<input type='hidden' name='email' value='{b['email']}'/>"
        f"<button type='submit'>Unban</button></form></td></tr>"
        for b in bans
    )
    html = f"""
    <html><head><title>tblock.fk bans</title>
    <style>body{{font-family:sans-serif;background:#0b1221;color:#e5e7eb;padding:20px;}}
    table{{width:100%;border-collapse:collapse;margin-top:10px;}}td,th{{padding:8px;border-bottom:1px solid #1f2937;}}
    input,button{{padding:8px;border-radius:6px;border:1px solid #1f2937;background:#111827;color:#e5e7eb;}}
    .card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:12px;margin-bottom:12px;}}
    </style></head><body>
    <h2>tblock.fk · ban manager</h2>
    <div class="card">Total: {stats['total']} · Banned: {stats['banned']} · Unbanned: {stats['unbanned']}</div>
    <form method="get"><input name="q" placeholder="Search email" value="{q}"/> <button type="submit">Search</button></form>
    <table><thead><tr><th>Email</th><th>IP</th><th>Domain</th><th>Status</th><th>When</th><th>Action</th></tr></thead>
    <tbody>{rows}</tbody></table>
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
