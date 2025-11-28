import sqlite3
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone


class BanStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute(
            """
            create table if not exists bans (
                id integer primary key autoincrement,
                email text,
                ip text,
                domain text,
                reason text,
                status text,
                created_at text,
                updated_at text
            )
            """
        )
        conn.commit()
        conn.close()

    def add(self, email: str, ip: str, domain: str, reason: str = "torrenting") -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute(
            "insert into bans (email, ip, domain, reason, status, created_at, updated_at) values (?,?,?,?,?,?,?)",
            (email, ip, domain, reason, "banned", now, now),
        )
        conn.commit()
        conn.close()

    def list(self, search: str = "") -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        if search:
            cur.execute(
                "select id,email,ip,domain,reason,status,created_at from bans where email like ? order by created_at desc",
                (f"%{search}%",),
            )
        else:
            cur.execute("select id,email,ip,domain,reason,status,created_at from bans order by created_at desc")
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "email": r[1],
                "ip": r[2],
                "domain": r[3],
                "reason": r[4],
                "status": r[5],
                "created_at": r[6],
            }
            for r in rows
        ]

    def stats(self) -> Dict[str, int]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("select count(*) from bans")
        total = cur.fetchone()[0]
        conn.close()
        return {"total": total}

    def is_banned(self, email: str) -> bool:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("select 1 from bans where email=? limit 1", (email,))
        row = cur.fetchone()
        conn.close()
        return row is not None

    def mark_unbanned(self, email: str) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute(
            "delete from bans where email=?",
            (email,),
        )
        conn.commit()
        conn.close()
