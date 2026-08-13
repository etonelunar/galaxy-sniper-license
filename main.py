from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
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
            revoked INTEGER DEFAULT 0,
            duration_seconds INTEGER,
            expires_at TEXT
        )
    """)
    conn.commit()

    # После ошибки PostgreSQL нужен rollback, иначе следующие ALTER не сработают
    for col, typedef in [
        ("revoked", "INTEGER DEFAULT 0"),
        ("duration_seconds", "INTEGER"),
        ("expires_at", "TEXT"),
    ]:
        try:
            cur.execute(f"ALTER TABLE licenses ADD COLUMN {col} {typedef}")
            conn.commit()
        except Exception:
            conn.rollback()

    cur.close()
    conn.close()


init_db()


def _now() -> datetime:
    return datetime.utcnow()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _is_expired(row: dict) -> bool:
    exp = _parse_dt(row.get("expires_at"))
    if exp is None:
        return False
    return _now() >= exp


def _status_of(row: dict) -> str:
    if row.get("revoked") == 1:
        return "revoked"
    if _is_expired(row):
        return "expired"
    if row.get("used") == 1:
        return "used"
    return "available"


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
    # Срок с момента активации. Если оба None → permanent
    duration_days: Optional[int] = Field(default=None, ge=0)
    duration_hours: Optional[int] = Field(default=None, ge=0)
    duration_seconds: Optional[int] = Field(default=None, ge=0)  # для тестов


class ExtendKeyRequest(BaseModel):
    key: str
    duration_days: Optional[int] = Field(default=None, ge=0)
    duration_hours: Optional[int] = Field(default=None, ge=0)
    permanent: bool = False


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

    if _is_expired(row):
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key expired"}

    if row["used"] == 1:
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key already used"}

    now = _now()
    duration_seconds = row.get("duration_seconds")
    expires_at = None
    if duration_seconds is not None and duration_seconds > 0:
        expires_at = (now + timedelta(seconds=int(duration_seconds))).isoformat()

    cur.execute(
        """
        UPDATE licenses
        SET used = 1,
            used_at = %s,
            hwid = %s,
            expires_at = %s
        WHERE key = %s
        """,
        (now.isoformat(), hwid, expires_at, key),
    )
    conn.commit()
    cur.close()
    conn.close()

    token = hmac.new(
        ADMIN_SECRET.encode(),
        f"{key}|{hwid}|{now.isoformat()}".encode(),
        hashlib.sha256
    ).hexdigest()

    return {
        "valid": True,
        "message": "Activated successfully",
        "token": token,
        "expires_at": expires_at,
        "permanent": expires_at is None,
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

    if _is_expired(row):
        return {"valid": False, "message": "expired"}

    if row["used"] != 1:
        return {"valid": False, "message": "Key not activated"}

    stored_hwid = (row["hwid"] or "").strip()
    if stored_hwid and stored_hwid != hwid:
        return {"valid": False, "message": "HWID mismatch"}

    return {
        "valid": True,
        "message": "OK",
        "expires_at": row.get("expires_at"),
        "permanent": row.get("expires_at") is None,
    }


# ---------- Admin endpoints ----------
@app.post("/admin/reset")
def reset_license(data: ResetKeyRequest, x_admin_secret: str = Header(...)):
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
            """
            UPDATE licenses
            SET used = 0, used_at = NULL, hwid = NULL, expires_at = NULL
            WHERE key = %s
            """,
            (key,),
        )
        reset_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur.execute(
            "SELECT key FROM licenses WHERE hwid = %s AND used = 1",
            (hwid,),
        )
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                """
                UPDATE licenses
                SET used = 0, used_at = NULL, hwid = NULL, expires_at = NULL
                WHERE key = %s
                """,
                (row["key"],),
            )
            reset_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()

    return {"ok": True, "reset": reset_keys, "count": len(reset_keys)}


@app.post("/admin/revoke")
def revoke_key(data: RevokeKeyRequest, x_admin_secret: str = Header(...)):
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
        cur.execute("UPDATE licenses SET revoked = 1 WHERE key = %s", (key,))
        revoked_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur.execute("SELECT key FROM licenses WHERE hwid = %s", (hwid,))
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                "UPDATE licenses SET revoked = 1 WHERE key = %s",
                (row["key"],),
            )
            revoked_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()

    return {"ok": True, "revoked": revoked_keys, "count": len(revoked_keys)}


@app.post("/admin/delete")
def delete_key(data: DeleteKeyRequest, x_admin_secret: str = Header(...)):
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

    return {"ok": True, "message": "Key deleted", "deleted": key}


@app.post("/admin/add-keys")
def add_keys(data: AddKeyRequest, x_admin_secret: str = Header(...)):
    """
    Примеры:
      {"count": 3}
      {"count": 5, "duration_days": 30}
      {"key": "VIP1", "duration_days": 7}
      {"count": 2, "duration_hours": 12}
      {"count": 1, "duration_seconds": 60}
    """
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    days = data.duration_days or 0
    hours = data.duration_hours or 0
    secs = data.duration_seconds or 0
    total = days * 86400 + hours * 3600 + secs
    duration_seconds = total if total > 0 else None

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
                """
                INSERT INTO licenses
                    (key, used, created_at, revoked, duration_seconds, expires_at)
                VALUES
                    (%s, 0, %s, 0, %s, NULL)
                """,
                (key, _now().isoformat(), duration_seconds),
            )
            created.append({
                "key": key,
                "permanent": duration_seconds is None,
                "duration_seconds": duration_seconds,
                "duration_days": (duration_seconds // 86400) if duration_seconds else None,
                "duration_hours": (
                    (duration_seconds % 86400) // 3600 if duration_seconds else None
                ),
            })
            if data.key:
                break
        except psycopg2.IntegrityError:
            conn.rollback()
            continue

    conn.commit()
    cur.close()
    conn.close()

    return {
        "created": created,
        "count": len(created),
        "permanent": duration_seconds is None,
        "duration_seconds": duration_seconds,
    }


@app.post("/admin/extend")
def extend_key(data: ExtendKeyRequest, x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    key = data.key.strip().upper()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM licenses WHERE key = %s", (key,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return {"ok": False, "message": "Key not found"}

    if data.permanent:
        cur.execute(
            """
            UPDATE licenses
            SET duration_seconds = NULL, expires_at = NULL
            WHERE key = %s
            """,
            (key,),
        )
        conn.commit()
        cur.close()
        conn.close()
        return {"ok": True, "key": key, "permanent": True, "expires_at": None}

    days = data.duration_days or 0
    hours = data.duration_hours or 0
    add_seconds = days * 86400 + hours * 3600
    if add_seconds <= 0:
        cur.close()
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Укажи duration_days/duration_hours или permanent=true",
        )

    now = _now()
    current_exp = _parse_dt(row.get("expires_at"))
    base = current_exp if (current_exp and current_exp > now) else now
    new_exp = base + timedelta(seconds=add_seconds)

    used_at = _parse_dt(row.get("used_at"))
    if used_at:
        duration_seconds = int((new_exp - used_at).total_seconds())
    else:
        old_dur = row.get("duration_seconds") or 0
        duration_seconds = int(old_dur) + add_seconds

    cur.execute(
        """
        UPDATE licenses
        SET expires_at = %s, duration_seconds = %s, revoked = 0
        WHERE key = %s
        """,
        (new_exp.isoformat(), duration_seconds, key),
    )
    conn.commit()
    cur.close()
    conn.close()

    return {
        "ok": True,
        "key": key,
        "permanent": False,
        "expires_at": new_exp.isoformat(),
        "duration_seconds": duration_seconds,
    }


@app.get("/admin/list-keys")
def list_keys(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT key, used, used_at, created_at, hwid, revoked,
               duration_seconds, expires_at
        FROM licenses
        ORDER BY created_at DESC NULLS LAST
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    keys = []
    for row in rows:
        status = _status_of(row)
        dur = row.get("duration_seconds")
        keys.append({
            "key": row["key"],
            "status": status,
            "used_at": row["used_at"],
            "created_at": row["created_at"],
            "hwid": row["hwid"],
            "revoked": bool(row.get("revoked") == 1),
            "permanent": dur is None and row.get("expires_at") is None,
            "duration_seconds": dur,
            "expires_at": row.get("expires_at"),
        })

    return {
        "total": len(keys),
        "available": sum(1 for k in keys if k["status"] == "available"),
        "used": sum(1 for k in keys if k["status"] == "used"),
        "revoked": sum(1 for k in keys if k["status"] == "revoked"),
        "expired": sum(1 for k in keys if k["status"] == "expired"),
        "keys": keys,
    }


@app.get("/admin/stats")
def stats(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key, used, revoked, expires_at FROM licenses")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    total = len(rows)
    available = used = revoked = expired = 0
    for row in rows:
        st = _status_of(row)
        if st == "available":
            available += 1
        elif st == "used":
            used += 1
        elif st == "revoked":
            revoked += 1
        elif st == "expired":
            expired += 1

    return {
        "total": total,
        "available": available,
        "used": used,
        "revoked": revoked,
        "expired": expired,
    }
