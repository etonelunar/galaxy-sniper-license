from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import os
import secrets

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
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class ActivateRequest(BaseModel):
    key: str

class AddKeyRequest(BaseModel):
    key: str = None          # если не указать — сгенерируется сам
    count: int = 1           # сколько ключей создать

@app.get("/")
def root():
    return {"status": "ok", "service": "Galaxy Sniper License"}

@app.post("/activate")
def activate(data: ActivateRequest):
    key = data.key.strip().upper()

    if not key:
        return {"valid": False, "message": "Empty key"}

    conn = get_db()
    cur = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,))
    row = cur.fetchone()

    if row is None:
        conn.close()
        return {"valid": False, "message": "Key not found"}

    if row["used"] == 1:
        conn.close()
        return {"valid": False, "message": "Key already used"}

    # Помечаем ключ использованным
    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE licenses SET used = 1, used_at = ? WHERE key = ?",
        (now, key)
    )
    conn.commit()
    conn.close()

    # Генерируем токен активации (его будет хранить программа)
    import hashlib, hmac
    secret = os.getenv("ADMIN_SECRET", "change-me")
    token = hmac.new(
        secret.encode(),
        f"{key}:{now}".encode(),
        hashlib.sha256
    ).hexdigest()

    return {
        "valid": True,
        "message": "Activated successfully",
        "token": token
    }

@app.post("/admin/add-keys")
def add_keys(data: AddKeyRequest, x_admin_secret: str = Header(...)):
    """Добавление новых ключей. Требует заголовок X-Admin-Secret"""
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    conn = get_db()
    created = []

    for _ in range(max(1, min(data.count, 50))):  # максимум 50 за раз
        if data.key:
            key = data.key.strip().upper()
        else:
            key = secrets.token_hex(8).upper()  # пример: A1B2C3D4E5F67890

        try:
            conn.execute(
                "INSERT INTO licenses (key, used, created_at) VALUES (?, 0, ?)",
                (key, datetime.utcnow().isoformat())
            )
            created.append(key)
        except sqlite3.IntegrityError:
            # ключ уже существует
            pass

    conn.commit()
    conn.close()

    return {"created": created, "count": len(created)}

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
