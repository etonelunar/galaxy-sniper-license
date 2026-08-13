from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import os
import secrets
import hashlib
import hmac
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Galaxy Sniper License Server")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-to-something-long")


def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            used_at TEXT,
            created_at TEXT,
            hwid TEXT,
            revoked INTEGER DEFAULT 0
        )
    """)
    try:
        cur.execute("ALTER TABLE licenses ADD COLUMN revoked INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    cur.close()
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


class RevokeKeyRequest(BaseModel):
    key: Optional[str] = None
    hwid: Optional[str] = None


class DeleteKeyRequest(BaseModel):
    key: str


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
    cur = conn.cursor()

    cur.execute("SELECT * FROM licenses WHERE key = %s", (key,))
    row = cur.fetchone()

    if row is None:
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key not found"}

    if row.get("revoked") == 1:
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key revoked"}

    if row["used"] == 1:
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key already used"}

    now = datetime.utcnow().isoformat()
    cur.execute(
        "UPDATE licenses SET used = 1, used_at = %s, hwid = %s WHERE key = %s",
        (now, hwid, key)
    )
    conn.commit()
    cur.close()
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
    cur = conn.cursor()
    cur.execute("SELECT * FROM licenses WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row is None:
        return {"valid": False, "message": "Key not found"}

    if row.get("revoked") == 1:
        return {"valid": False, "message": "revoked"}

    if row["used"] != 1:
        return {"valid": False, "message": "Key not activated"}

    stored_hwid = (row["hwid"] or "").strip()
    if stored_hwid and stored_hwid != hwid:
        return {"valid": False, "message": "HWID mismatch"}

    return {"valid": True, "message": "OK"}


# ---------- Admin endpoints ----------
@app.post("/admin/reset")
def reset_license(data: ResetKeyRequest, x_admin_secret: str = Header(...)):
    """
    Сброс активации:
    - по key  → ключ снова available (used=0, hwid=NULL), revoked не трогаем
    - по hwid → все ключи этого ПК снова available
    """
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not data.key and not data.hwid:
        raise HTTPException(status_code=400, detail="Укажи key или hwid")

    conn = get_db()
    cur = conn.cursor()
    reset_keys = []

    if data.key:
        key = data.key.strip().upper()
        cur.execute("SELECT key FROM licenses WHERE key = %s", (key,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return {"ok": False, "message": "Key not found", "reset": []}
        cur.execute(
            "UPDATE licenses SET used = 0, used_at = NULL, hwid = NULL WHERE key = %s",
            (key,)
        )
        reset_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur.execute(
            "SELECT key FROM licenses WHERE hwid = %s AND used = 1",
            (hwid,)
        )
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                "UPDATE licenses SET used = 0, used_at = NULL, hwid = NULL WHERE key = %s",
                (row["key"],)
            )
            reset_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()

    return {
        "ok": True,
        "reset": reset_keys,
        "count": len(reset_keys)
    }


@app.post("/admin/revoke")
def revoke_key(data: RevokeKeyRequest, x_admin_secret: str = Header(...)):
    """
    Отзыв доступа:
    - по key  → этот ключ revoked
    - по hwid → все ключи этого ПК revoked
    Клиент при старте получит message "revoked" и сбросит локальную активацию.
    """
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not data.key and not data.hwid:
        raise HTTPException(status_code=400, detail="Укажи key или hwid")

    conn = get_db()
    cur = conn.cursor()
    revoked_keys = []

    if data.key:
        key = data.key.strip().upper()
        cur.execute("SELECT key FROM licenses WHERE key = %s", (key,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return {"ok": False, "message": "Key not found", "revoked": []}
        cur.execute(
            "UPDATE licenses SET revoked = 1 WHERE key = %s",
            (key,)
        )
        revoked_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur.execute(
            "SELECT key FROM licenses WHERE hwid = %s",
            (hwid,)
        )
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                "UPDATE licenses SET revoked = 1 WHERE key = %s",
                (row["key"],)
            )
            revoked_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()

    return {
        "ok": True,
        "revoked": revoked_keys,
        "count": len(revoked_keys)
    }


@app.post("/admin/delete")
def delete_key(data: DeleteKeyRequest, x_admin_secret: str = Header(...)):
    """Полное удаление ключа из базы."""
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    key = (data.key or "").strip().upper()
    if not key:
        raise HTTPException(status_code=400, detail="Укажи key")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT key FROM licenses WHERE key = %s", (key,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return {"ok": False, "message": "Key not found", "deleted": None}

    cur.execute("DELETE FROM licenses WHERE key = %s", (key,))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "ok": True,
        "message": "Key deleted",
        "deleted": key
    }


@app.post("/admin/add-keys")
def add_keys(data: AddKeyRequest, x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    cur = conn.cursor()
    created = []

    for _ in range(max(1, min(data.count, 50))):
        if data.key:
            key = data.key.strip().upper()
        else:
            key = secrets.token_hex(8).upper()

        try:
            cur.execute(
                "INSERT INTO licenses (key, used, created_at, revoked) VALUES (%s, 0, %s, 0)",
                (key, datetime.utcnow().isoformat())
            )
            created.append(key)
        except psycopg2.IntegrityError:
            conn.rollback()
            continue

    conn.commit()
    cur.close()
    conn.close()

    return {"created": created, "count": len(created)}


@app.get("/admin/list-keys")
def list_keys(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT key, used, used_at, created_at, hwid, revoked "
        "FROM licenses ORDER BY created_at DESC NULLS LAST"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    keys = []
    for row in rows:
        if row.get("revoked") == 1:
            status = "revoked"
        elif row["used"] == 1:
            status = "used"
        else:
            status = "available"

        keys.append({
            "key": row["key"],
            "status": status,
            "used_at": row["used_at"],
            "created_at": row["created_at"],
            "hwid": row["hwid"],
            "revoked": bool(row.get("revoked") == 1)
        })

    return {
        "total": len(keys),
        "available": sum(1 for k in keys if k["status"] == "available"),
        "used": sum(1 for k in keys if k["status"] == "used"),
        "revoked": sum(1 for k in keys if k["status"] == "revoked"),
        "keys": keys
    }


@app.get("/admin/stats")
def stats(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM licenses")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS used FROM licenses WHERE used = 1 AND COALESCE(revoked, 0) = 0")
    used = cur.fetchone()["used"]

    cur.execute("SELECT COUNT(*) AS revoked FROM licenses WHERE COALESCE(revoked, 0) = 1")
    revoked = cur.fetchone()["revoked"]

    cur.execute(
        "SELECT COUNT(*) AS available FROM licenses "
        "WHERE used = 0 AND COALESCE(revoked, 0) = 0"
    )
    available = cur.fetchone()["available"]

    cur.close()
    conn.close()

    return {
        "total": total,
        "used": used,
        "available": available,
        "revoked": revoked
    }
