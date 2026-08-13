from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import sqlite3
import os
import secrets
import hashlib
import hmac

app = FastAPI(title="Galaxy Sniper License Server")

DB_PATH = "licenses.db"
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-to-something-long")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            used_at TEXT,
            created_at TEXT,
            hwid TEXT
        )
    """)
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN hwid TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


init_db()


# ---------- Models ----------
class ActivateRequest(BaseModel):
    key: str
    hwid: str


class ValidateRequest(BaseModel):
    key: str
    hwid: str


class ResetKeyRequest(BaseModel):
    key: Optional[str] = None
    hwid: Optional[str] = None


class AddKeyRequest(BaseModel):
    key: Optional[str] = None
    count: int = 1


# ---------- Public endpoints ----------
@app.get("/")
def root():
    return {"status": "ok", "service": "Galaxy Sniper License"}


@app.post("/activate")
def activate(data: ActivateRequest):
    key = data.key.strip().upper()
    hwid = (data.hwid or "").strip()

    if not key:
        return {"valid": False, "message": "Empty key"}
    if not hwid:
        return {"valid": False, "message": "Empty HWID"}

    conn = get_db()
    cur = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,))
    row = cur.fetchone()

    if row is None:
        conn.close()
        return {"valid": False, "message": "Key not found"}

    if row["used"] == 1:
        conn.close()
        return {"valid": False, "message": "Key already used"}

    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE licenses SET used = 1, used_at = ?, hwid = ? WHERE key = ?",
        (now, hwid, key)
    )
    conn.commit()
    conn.close()

    token = hmac.new(
        ADMIN_SECRET.encode(),
        f"{key}|{hwid}|{now}".encode(),
        hashlib.sha256
    ).hexdigest()

    return {
        "valid": True,
        "message": "Activated successfully",
        "token": token
    }


@app.post("/validate")
def validate(data: ValidateRequest):
    key = data.key.strip().upper()
    hwid = (data.hwid or "").strip()

    if not key:
        return {"valid": False, "message": "Empty key"}
    if not hwid:
        return {"valid": False, "message": "Empty HWID"}

    conn = get_db()
    cur = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        # После сна/деплоя на free Render БД часто пустая —
        # клиент должен сохранить локальную активацию
        return {"valid": False, "message": "Key not found"}

    if row["used"] != 1:
        return {"valid": False, "message": "Key not activated"}

    stored_hwid = (row["hwid"] or "").strip()
    if stored_hwid and stored_hwid != hwid:
        return {"valid": False, "message": "HWID mismatch"}

    return {"valid": True, "message": "OK"}


# ---------- Admin endpoints ----------
@app.post("/admin/reset")
def reset_license(data: ResetKeyRequest, x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not data.key and not data.hwid:
        raise HTTPException(status_code=400, detail="Укажи key или hwid")

    conn = get_db()
    reset_keys = []

    if data.key:
        key = data.key.strip().upper()
        cur = conn.execute("SELECT key FROM licenses WHERE key = ?", (key,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return {"ok": False, "message": "Key not found", "reset": []}
        conn.execute(
            "UPDATE licenses SET used = 0, used_at = NULL, hwid = NULL WHERE key = ?",
            (key,)
        )
        reset_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur = conn.execute(
            "SELECT key FROM licenses WHERE hwid = ? AND used = 1",
            (hwid,)
        )
        rows = cur.fetchall()
        for row in rows:
            conn.execute(
                "UPDATE licenses SET used = 0, used_at = NULL, hwid = NULL WHERE key = ?",
                (row["key"],)
            )
            reset_keys.append(row["key"])

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "reset": reset_keys,
        "count": len(reset_keys)
    }


@app.post("/admin/add-keys")
def add_keys(data: AddKeyRequest, x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    created = []

    for _ in range(max(1, min(data.count, 50))):
        if data.key:
            key = data.key.strip().upper()
        else:
            key = secrets.token_hex(8).upper()

        try:
            conn.execute(
                "INSERT INTO licenses (key, used, created_at) VALUES (?, 0, ?)",
                (key, datetime.utcnow().isoformat())
            )
            created.append(key)
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()

    return {"created": created, "count": len(created)}


@app.get("/admin/list-keys")
def list_keys(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    rows = conn.execute(
        "SELECT key, used, used_at, created_at, hwid FROM licenses ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    keys = []
    for row in rows:
        keys.append({
            "key": row["key"],
            "status": "used" if row["used"] == 1 else "available",
            "used_at": row["used_at"],
            "created_at": row["created_at"],
            "hwid": row["hwid"]
        })

    return {
        "total": len(keys),
        "available": sum(1 for k in keys if k["status"] == "available"),
        "used": sum(1 for k in keys if k["status"] == "used"),
        "keys": keys
    }


@app.get("/admin/stats")
def stats(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    used = conn.execute("SELECT COUNT(*) FROM licenses WHERE used = 1").fetchone()[0]
    free = total - used
    conn.close()

    return {"total": total, "used": used, "available": free}
