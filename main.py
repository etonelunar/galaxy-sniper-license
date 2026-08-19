"""
Galaxy Sniper License Server
+ force-update / kill-switch
+ rate-limit, longer keys, bulk admin, notes
+ update_sha256 for safe auto-update
+ key_type (basic | free | premium)
+ basic = 1 queue, no premium UI features; unlimited activations per HWID
+ free  = Premium feature set; only ONE activation ever per HWID (legacy: free_2d)
+ premium = full features; unlimited activations per HWID
+ admin can clear free HWID block (free_2d_claims table kept for compatibility)
"""

from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from collections import defaultdict, deque
import os
import secrets
import hashlib
import hmac
import threading
import time
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Galaxy Sniper License Server")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

ADMIN_SECRET = os.getenv("ADMIN_SECRET")
if not ADMIN_SECRET or ADMIN_SECRET == "change-me-to-something-long":
    if os.getenv("ALLOW_INSECURE_ADMIN_SECRET", "").lower() not in ("1", "true", "yes"):
        raise RuntimeError(
            "ADMIN_SECRET must be set to a long random value "
            "(not the default). Set ALLOW_INSECURE_ADMIN_SECRET=1 only for local dev."
        )
    ADMIN_SECRET = ADMIN_SECRET or "change-me-to-something-long"

SERVER_LATEST_VERSION = os.getenv("LATEST_VERSION", "1.0.0")

# ── Rate limit (in-memory; fine for single Render instance) ──
_RATE_LOCK = threading.Lock()
_RATE_BUCKETS: Dict[str, deque] = defaultdict(deque)

RATE_LIMITS = {
    "activate": (12, 60),
    "validate": (30, 60),
    "client_check": (20, 60),
    "activate_key": (8, 300),
}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_check(bucket_key: str, limit: int, window_sec: int) -> Optional[str]:
    now = time.time()
    with _RATE_LOCK:
        q = _RATE_BUCKETS[bucket_key]
        while q and q[0] <= now - window_sec:
            q.popleft()
        if len(q) >= limit:
            return f"Rate limit exceeded. Try again in {window_sec}s."
        q.append(now)
    return None


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


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
            expires_at TEXT,
            note TEXT DEFAULT '',
            batch_id TEXT DEFAULT '',
            key_type TEXT DEFAULT 'premium'
        )
    """)
    conn.commit()

    for col, typedef in [
        ("revoked", "INTEGER DEFAULT 0"),
        ("duration_seconds", "INTEGER"),
        ("expires_at", "TEXT"),
        ("note", "TEXT DEFAULT ''"),
        ("batch_id", "TEXT DEFAULT ''"),
        ("key_type", "TEXT DEFAULT 'premium'"),
    ]:
        try:
            cur.execute(f"ALTER TABLE licenses ADD COLUMN {col} {typedef}")
            conn.commit()
        except Exception:
            conn.rollback()

    # Backfill NULL key_type → premium
    try:
        cur.execute(
            "UPDATE licenses SET key_type = 'premium' WHERE key_type IS NULL OR key_type = ''"
        )
        conn.commit()
    except Exception:
        conn.rollback()

    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_used ON licenses(used)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_revoked ON licenses(revoked)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_batch ON licenses(batch_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_key_type ON licenses(key_type)")
        conn.commit()
    except Exception:
        conn.rollback()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS free_2d_claims (
            hwid TEXT PRIMARY KEY,
            key TEXT,
            claimed_at TEXT
        )
    """)
    conn.commit()
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_free_2d_claims_key ON free_2d_claims(key)")
        conn.commit()
    except Exception:
        conn.rollback()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS license_accounts (
            id SERIAL PRIMARY KEY,
            key TEXT NOT NULL,
            account_id TEXT NOT NULL,
            account_name TEXT DEFAULT '',
            hwid TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    try:
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_license_accounts_key_acc "
            "ON license_accounts(key, account_id)"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_lic_acc_key ON license_accounts(key)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_lic_acc_name ON license_accounts(account_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_lic_acc_id ON license_accounts(account_id)")
        conn.commit()
    except Exception:
        conn.rollback()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS account_purges (
            id SERIAL PRIMARY KEY,
            key TEXT NOT NULL,
            account_id TEXT NOT NULL,
            purged_at TEXT,
            UNIQUE (key, account_id)
        )
    """)
    conn.commit()
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_account_purges_key ON account_purges(key)")
        conn.commit()
    except Exception:
        conn.rollback()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()

    defaults = {
        "force_update": "0",
        "min_version": "1.0.0",
        "latest_version": SERVER_LATEST_VERSION,
        "update_message": "Доступно обязательное обновление. Установите новую версию, чтобы продолжить.",
        "update_url": "",
        "update_sha256": "",
        "block_all": "0",
        "block_message": "Сервис временно недоступен. Обратитесь в поддержку.",
    }
    for k, v in defaults.items():
        cur.execute(
            """
            INSERT INTO app_config (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO NOTHING
            """,
            (k, v),
        )
    conn.commit()

    # One-time rename: free → basic, free_2d → free (order matters).
    try:
        cur.execute(
            "SELECT value FROM app_config WHERE key = %s",
            ("migrated_key_types_v2",),
        )
        row_m = cur.fetchone()
        already = bool(row_m and str(row_m.get("value") or "") == "1")
    except Exception:
        already = False
        try:
            conn.rollback()
        except Exception:
            pass

    if not already:
        try:
            cur.execute(
                "UPDATE licenses SET key_type = 'basic' WHERE lower(coalesce(key_type, '')) = 'free'"
            )
            cur.execute(
                "UPDATE licenses SET key_type = 'free' WHERE lower(coalesce(key_type, '')) IN "
                "('free_2d', 'free2d', '2_days_free', 'free_2days', 'trial')"
            )
            cur.execute(
                """
                INSERT INTO app_config (key, value) VALUES ('migrated_key_types_v2', '1')
                ON CONFLICT (key) DO UPDATE SET value = '1'
                """
            )
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass

    cur.close()
    conn.close()


init_db()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
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


def _normalize_key_type(value: Optional[str]) -> str:
    v = (value or "premium").strip().lower()
    # legacy aliases → current names
    if v in ("free_2d", "free2d", "2_days_free", "free_2days", "trial"):
        v = "free"  # once-per-HWID plan (was free_2d)
    elif v == "free":
        # bare "free" in *new* API means once-per-HWID Free plan.
        # Legacy DB rows were migrated free→basic in init_db.
        # If a client still sends old "free" meaning Basic, accept "basic" explicitly.
        v = "free"
    if v in ("basic", "free", "premium"):
        return v
    return "premium"


def _is_limited_plan(key_type: Optional[str]) -> bool:
    """Basic only: 1 queue / no premium client features.

    Free is treated as full-feature (like Premium) for client limits;
    once-per-HWID is enforced separately on activation via free_2d_claims.
    """
    return _normalize_key_type(key_type) == "basic"


def _client_key_type(key_type: Optional[str]) -> str:
    """What the desktop app stores/displays: basic | free | premium."""
    kt = _normalize_key_type(key_type)
    if kt in ("basic", "free"):
        return kt
    return "premium"


def _get_config() -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM app_config")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def _set_config(updates: dict):
    conn = get_db()
    cur = conn.cursor()
    for k, v in updates.items():
        cur.execute(
            """
            INSERT INTO app_config (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (k, str(v) if v is not None else ""),
        )
    conn.commit()
    cur.close()
    conn.close()


def _parse_version(v: str):
    if not v:
        return (0, 0, 0)
    parts = []
    for p in str(v).strip().lstrip("vV").split("."):
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _version_less(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _gen_key() -> str:
    raw = secrets.token_hex(16).upper()
    return f"{raw[0:8]}-{raw[8:16]}-{raw[16:24]}-{raw[24:32]}"


def _normalize_key(value: str) -> str:
    return "".join(c for c in (value or "").upper() if c.isalnum())


def _require_admin(secret: str):
    if not secret or not hmac.compare_digest(secret, ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden")


def _find_license(cur, key_raw: str):
    key = (key_raw or "").strip().upper()
    if not key:
        return None, ""
    cur.execute("SELECT * FROM licenses WHERE key = %s", (key,))
    row = cur.fetchone()
    if row:
        return row, key
    plain = _normalize_key(key)
    if plain and plain != key:
        cur.execute(
            "SELECT * FROM licenses WHERE REPLACE(key, '-', '') = %s",
            (plain,),
        )
        row = cur.fetchone()
        if row:
            return row, row["key"]
    return None, key



def _accounts_for_key(cur, key: str) -> list:
    try:
        cur.execute(
            """
            SELECT account_id, account_name, hwid, first_seen, last_seen
            FROM license_accounts
            WHERE key = %s
            ORDER BY last_seen DESC NULLS LAST
            """,
            (key,),
        )
        return [dict(r) for r in (cur.fetchall() or [])]
    except Exception:
        return []


def _accounts_for_keys(cur, keys: list) -> dict:
    """key -> list of accounts"""
    out = {k: [] for k in keys}
    if not keys:
        return out
    try:
        cur.execute(
            """
            SELECT key, account_id, account_name, hwid, first_seen, last_seen
            FROM license_accounts
            WHERE key = ANY(%s)
            ORDER BY last_seen DESC NULLS LAST
            """,
            (list(keys),),
        )
        for r in cur.fetchall() or []:
            k = r["key"]
            if k in out:
                out[k].append({
                    "account_id": r.get("account_id"),
                    "account_name": r.get("account_name") or "",
                    "hwid": r.get("hwid") or "",
                    "first_seen": r.get("first_seen"),
                    "last_seen": r.get("last_seen"),
                })
    except Exception:
        pass
    return out


def _purges_for_key(cur, key: str) -> list:
    try:
        cur.execute(
            "SELECT account_id FROM account_purges WHERE key = %s",
            (key,),
        )
        return [str(r["account_id"]) for r in (cur.fetchall() or []) if r.get("account_id")]
    except Exception:
        return []


def _purge_accounts_admin(cur, key: str, account_ids: list | None) -> list:
    """Remove accounts from license_accounts and queue client-side purge.

    If account_ids is None/empty — purge ALL accounts for the key.
    Returns list of account_ids that were purged.
    """
    key = (key or "").strip().upper()
    if not key:
        return []
    purged = []
    if account_ids:
        ids = [str(a).strip() for a in account_ids if str(a).strip()]
        for aid in ids:
            cur.execute(
                "DELETE FROM license_accounts WHERE key = %s AND account_id = %s RETURNING account_id",
                (key, aid),
            )
            row = cur.fetchone()
            if row:
                purged.append(str(row["account_id"]))
            else:
                purged.append(aid)  # still force client remove
            cur.execute(
                """
                INSERT INTO account_purges (key, account_id, purged_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (key, account_id) DO UPDATE SET purged_at = EXCLUDED.purged_at
                """,
                (key, aid, _now().isoformat()),
            )
    else:
        cur.execute(
            "DELETE FROM license_accounts WHERE key = %s RETURNING account_id",
            (key,),
        )
        rows = cur.fetchall() or []
        for r in rows:
            aid = str(r["account_id"])
            purged.append(aid)
            cur.execute(
                """
                INSERT INTO account_purges (key, account_id, purged_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (key, account_id) DO UPDATE SET purged_at = EXCLUDED.purged_at
                """,
                (key, aid, _now().isoformat()),
            )
    return purged


def _row_to_key(row: dict) -> dict:
    status = _status_of(row)
    dur = row.get("duration_seconds")
    return {
        "key": row["key"],
        "status": status,
        "key_type": _normalize_key_type(row.get("key_type")),
        "used_at": row.get("used_at"),
        "created_at": row.get("created_at"),
        "hwid": row.get("hwid"),
        "revoked": bool(row.get("revoked") == 1),
        "permanent": dur is None and row.get("expires_at") is None,
        "duration_seconds": dur,
        "expires_at": row.get("expires_at"),
        "note": row.get("note") or "",
        "batch_id": row.get("batch_id") or "",
    }


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
    keys: Optional[List[str]] = None


class RevokeKeyRequest(BaseModel):
    key: Optional[str] = None
    hwid: Optional[str] = None
    keys: Optional[List[str]] = None


class DeleteKeyRequest(BaseModel):
    key: Optional[str] = None
    keys: Optional[List[str]] = None


class AddKeyRequest(BaseModel):
    key: Optional[str] = None
    count: int = Field(default=1, ge=1, le=200)
    duration_days: Optional[int] = Field(default=None, ge=0)
    duration_hours: Optional[int] = Field(default=None, ge=0)
    duration_seconds: Optional[int] = Field(default=None, ge=0)
    note: Optional[str] = None
    batch_id: Optional[str] = None
    prefix: Optional[str] = None
    key_type: Optional[str] = "premium"


class ExtendKeyRequest(BaseModel):
    key: Optional[str] = None
    keys: Optional[List[str]] = None
    duration_days: Optional[int] = Field(default=None, ge=0)
    duration_hours: Optional[int] = Field(default=None, ge=0)
    permanent: bool = False


class NoteKeyRequest(BaseModel):
    key: str
    note: str = ""


class SetKeyTypeRequest(BaseModel):
    key: Optional[str] = None
    keys: Optional[List[str]] = None
    key_type: str = "premium"


class ClientCheckRequest(BaseModel):
    version: str
    hwid: Optional[str] = None


class ForceUpdateRequest(BaseModel):
    force_update: Optional[bool] = None
    block_all: Optional[bool] = None
    min_version: Optional[str] = None
    latest_version: Optional[str] = None
    update_message: Optional[str] = None
    update_url: Optional[str] = None
    update_sha256: Optional[str] = None
    block_message: Optional[str] = None


class BulkStatusRequest(BaseModel):
    keys: List[str]


# ---------- Public ----------
@app.get("/")
def root():
    return {"status": "ok", "service": "Galaxy Sniper License", "version": SERVER_LATEST_VERSION}


@app.get("/health")
def health():
    """Simple health check for monitoring."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "ok", "db": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"db error: {e}")


@app.post("/client/check")
def client_check(data: ClientCheckRequest, request: Request):
    ip = _client_ip(request)
    err = _rate_check(f"client_check:{ip}", *RATE_LIMITS["client_check"])
    if err:
        raise HTTPException(status_code=429, detail=err)

    cfg = _get_config()
    client_ver = (data.version or "").strip()
    min_ver = (cfg.get("min_version") or "1.0.0").strip()
    latest = (cfg.get("latest_version") or min_ver).strip()
    force = cfg.get("force_update") == "1"
    block_all = cfg.get("block_all") == "1"

    update_message = cfg.get("update_message") or ""
    update_url = cfg.get("update_url") or ""
    update_sha256 = (cfg.get("update_sha256") or "").strip().lower()
    block_message = cfg.get("block_message") or ""

    if block_all:
        return {
            "ok": False,
            "blocked": True,
            "force_update": False,
            "message": block_message or "Сервис временно недоступен.",
            "min_version": min_ver,
            "latest_version": latest,
            "update_url": update_url,
            "update_sha256": update_sha256,
            "client_version": client_ver,
        }

    needs_update = force and _version_less(client_ver, min_ver)
    outdated = _version_less(client_ver, latest)

    if needs_update:
        return {
            "ok": False,
            "blocked": False,
            "force_update": True,
            "message": update_message or "Требуется обновление.",
            "min_version": min_ver,
            "latest_version": latest,
            "update_url": update_url,
            "update_sha256": update_sha256,
            "client_version": client_ver,
        }

    return {
        "ok": True,
        "blocked": False,
        "force_update": False,
        "outdated": outdated,
        "message": "" if not outdated else (update_message or "Доступна новая версия."),
        "min_version": min_ver,
        "latest_version": latest,
        "update_url": update_url,
        "update_sha256": update_sha256,
        "client_version": client_ver,
    }



class ReportAccountsRequest(BaseModel):
    key: str
    hwid: str
    accounts: List[Dict[str, Any]] = []


@app.post("/client/report-accounts")
def report_accounts(data: ReportAccountsRequest, request: Request):
    """Client reports Discord accounts used with this license.

    Requires an activated key. HWID is preferred but a mismatch no longer
    blocks the write — admin still needs to see which Discord accounts use the key.
    """
    ip = _client_ip(request)
    err = _rate_check(f"report_acc:{ip}", 60, 60)
    if err:
        raise HTTPException(status_code=429, detail=err)

    key_in = (data.key or "").strip().upper()
    hwid = (data.hwid or "").strip()
    if not key_in:
        return {"ok": False, "message": "key required"}

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS license_accounts (
                id SERIAL PRIMARY KEY,
                key TEXT NOT NULL,
                account_id TEXT NOT NULL,
                account_name TEXT DEFAULT '',
                hwid TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_license_accounts_key_acc "
            "ON license_accounts(key, account_id)"
        )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass

    row, key = _find_license(cur, key_in)
    if row is None:
        cur.close()
        conn.close()
        return {"ok": False, "message": "Key not found"}
    if int(row.get("used") or 0) != 1:
        cur.close()
        conn.close()
        return {"ok": False, "message": "Key not activated"}

    # Prefer matching HWID, but do not hard-fail on mismatch (admin visibility)
    stored = (row.get("hwid") or "").strip()
    hwid_mismatch = bool(stored and hwid and stored != hwid)

    now = _now().isoformat()
    saved = 0
    errors = []
    purge_ids = set(_purges_for_key(cur, key))
    for acc in (data.accounts or [])[:30]:
        if not isinstance(acc, dict):
            continue
        aid = str(acc.get("id") or acc.get("account_id") or "").strip()
        aname = str(acc.get("name") or acc.get("account_name") or "").strip()[:128]
        if not aid:
            continue
        if aid in purge_ids:
            # Admin requested removal — do not re-register until client acks and user re-adds
            continue
        try:
            cur.execute("SAVEPOINT sp_acc")
            cur.execute(
                "SELECT id FROM license_accounts WHERE key = %s AND account_id = %s",
                (key, aid),
            )
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    UPDATE license_accounts
                    SET account_name = CASE WHEN %s <> '' THEN %s ELSE account_name END,
                        hwid = CASE WHEN %s <> '' THEN %s ELSE hwid END,
                        last_seen = %s
                    WHERE key = %s AND account_id = %s
                    """,
                    (aname, aname, hwid, hwid, now, key, aid),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO license_accounts (key, account_id, account_name, hwid, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (key, aid, aname, hwid, now, now),
                )
            cur.execute("RELEASE SAVEPOINT sp_acc")
            saved += 1
        except Exception as e:
            errors.append(f"{aid}:{str(e)[:120]}")
            try:
                cur.execute("ROLLBACK TO SAVEPOINT sp_acc")
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass

    try:
        conn.commit()
    except Exception as e:
        errors.append(f"commit:{e}")
        try:
            conn.rollback()
        except Exception:
            pass

    cur.close()
    conn.close()
    return {
        "ok": True,
        "saved": saved,
        "key": key,
        "hwid_mismatch": hwid_mismatch,
        "errors": errors[:5],
        "purge_account_ids": list(purge_ids),
    }


@app.get("/admin/key-accounts")
def admin_key_accounts(key: str, x_admin_secret: str = Header(...)):
    """Fetch Discord accounts linked to a license key."""
    _require_admin(x_admin_secret)
    key_in = (key or "").strip().upper()
    if not key_in:
        raise HTTPException(status_code=400, detail="key required")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS license_accounts (
                id SERIAL PRIMARY KEY,
                key TEXT NOT NULL,
                account_id TEXT NOT NULL,
                account_name TEXT DEFAULT '',
                hwid TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        conn.commit()
    except Exception:
        conn.rollback()
    row, key = _find_license(cur, key_in)
    accounts = _accounts_for_key(cur, key) if row else []
    cur.close()
    conn.close()
    return {"ok": True, "key": key, "accounts": accounts, "found": row is not None}



@app.post("/admin/remove-accounts")
def admin_remove_accounts(data: dict, x_admin_secret: str = Header(...)):
    """Remove Discord account(s) linked to a key.

    Body: { "key": "...", "account_ids": ["id1", ...] optional }
    If account_ids omitted/empty — remove ALL accounts for the key.
    Clients will drop these accounts on next validate/report.
    """
    _require_admin(x_admin_secret)
    key = (data.get("key") or "").strip().upper()
    if not key:
        raise HTTPException(status_code=400, detail="key required")
    raw_ids = data.get("account_ids") or data.get("account_id")
    if isinstance(raw_ids, str):
        account_ids = [raw_ids]
    elif isinstance(raw_ids, list):
        account_ids = raw_ids
    else:
        account_ids = None

    conn = get_db()
    cur = conn.cursor()
    try:
        purged = _purge_accounts_admin(cur, key, account_ids)
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    cur.close()
    conn.close()
    return {"ok": True, "key": key, "purged": purged, "count": len(purged)}


@app.post("/client/ack-purges")
def client_ack_purges(data: dict, request: Request):
    """Client confirms it removed purged accounts locally."""
    key = (data.get("key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()
    ids = data.get("account_ids") or []
    if not key or not ids:
        return {"ok": False, "message": "key and account_ids required"}
    conn = get_db()
    cur = conn.cursor()
    try:
        for aid in ids:
            aid = str(aid).strip()
            if not aid:
                continue
            cur.execute(
                "DELETE FROM account_purges WHERE key = %s AND account_id = %s",
                (key, aid),
            )
        conn.commit()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()
    return {"ok": True}


@app.post("/activate")
def activate(data: ActivateRequest, request: Request):
    ip = _client_ip(request)
    err = _rate_check(f"activate:{ip}", *RATE_LIMITS["activate"])
    if err:
        raise HTTPException(status_code=429, detail=err)

    hwid = (data.hwid or "").strip()
    if not (data.key or "").strip():
        return {"valid": False, "message": "Empty key"}
    if not hwid:
        return {"valid": False, "message": "Empty HWID"}

    cfg = _get_config()
    if cfg.get("block_all") == "1":
        return {
            "valid": False,
            "message": cfg.get("block_message") or "Сервис временно недоступен",
        }

    conn = get_db()
    cur = conn.cursor()
    row, key = _find_license(cur, data.key)

    err = _rate_check(f"activate_key:{_normalize_key(key)}", *RATE_LIMITS["activate_key"])
    if err:
        cur.close()
        conn.close()
        raise HTTPException(status_code=429, detail=err)

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

    key_type_pre = _normalize_key_type(row.get("key_type"))
    # Free (once-per-HWID) only: one claim per HWID for the entire Free pool
    if key_type_pre == "free":
        cur.execute("SELECT key FROM free_2d_claims WHERE hwid = %s LIMIT 1", (hwid,))
        already = cur.fetchone()
        if already:
            cur.close()
            conn.close()
            return {
                "valid": False,
                "message": "Free license already used on this device",
                "code": "free_already_used",
            }

    if row["used"] == 1:
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key already used"}

    now = _now()
    duration_seconds = row.get("duration_seconds")
    expires_at = None
    if duration_seconds is not None and duration_seconds > 0:
        expires_at = (now + timedelta(seconds=int(duration_seconds))).isoformat()

    key_type = _normalize_key_type(row.get("key_type"))

    cur.execute(
        """
        UPDATE licenses
        SET used = 1, used_at = %s, hwid = %s, expires_at = %s
        WHERE key = %s AND used = 0
        """,
        (now.isoformat(), hwid, expires_at, key),
    )
    if cur.rowcount == 0:
        conn.rollback()
        cur.close()
        conn.close()
        return {"valid": False, "message": "Key already used"}

    if key_type == "free":
        try:
            cur.execute(
                """
                INSERT INTO free_2d_claims (hwid, key, claimed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (hwid) DO NOTHING
                """,
                (hwid, key, now.isoformat()),
            )
            # If conflict slipped through race, roll back activation
            cur.execute("SELECT key FROM free_2d_claims WHERE hwid = %s", (hwid,))
            claim = cur.fetchone()
            if claim and claim.get("key") != key:
                conn.rollback()
                cur.close()
                conn.close()
                return {
                    "valid": False,
                    "message": "Free license already used on this device",
                    "code": "free_already_used",
                }
        except Exception:
            conn.rollback()
            cur.close()
            conn.close()
            return {
                "valid": False,
                "message": "Free license already used on this device",
                "code": "free_already_used",
            }

    conn.commit()
    cur.close()
    conn.close()

    token = hmac.new(
        ADMIN_SECRET.encode(),
        f"{key}|{hwid}|{now.isoformat()}".encode(),
        hashlib.sha256,
    ).hexdigest()

    return {
        "valid": True,
        "message": "Activated successfully",
        "token": token,
        "expires_at": expires_at,
        "permanent": expires_at is None,
        # Client receives basic | free | premium
        "key_type": _client_key_type(key_type),
    }


@app.post("/validate")
def validate(data: ValidateRequest, request: Request):
    ip = _client_ip(request)
    err = _rate_check(f"validate:{ip}", *RATE_LIMITS["validate"])
    if err:
        raise HTTPException(status_code=429, detail=err)

    hwid = (data.hwid or "").strip()
    if not (data.key or "").strip():
        return {"valid": False, "message": "Empty key"}
    if not hwid:
        return {"valid": False, "message": "Empty HWID"}

    cfg = _get_config()
    if cfg.get("block_all") == "1":
        return {
            "valid": False,
            "message": "blocked",
            "blocked": True,
            "block_message": cfg.get("block_message") or "Сервис временно недоступен",
        }

    conn = get_db()
    cur = conn.cursor()
    row, key = _find_license(cur, data.key)
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

    purge_ids = []
    try:
        conn2 = get_db()
        cur2 = conn2.cursor()
        purge_ids = _purges_for_key(cur2, key)
        cur2.close()
        conn2.close()
    except Exception:
        purge_ids = []

    return {
        "valid": True,
        "message": "OK",
        "expires_at": row.get("expires_at"),
        "permanent": row.get("expires_at") is None,
        "key_type": _client_key_type(row.get("key_type")),
        "purge_account_ids": purge_ids,
    }


# ---------- Admin ----------
@app.get("/admin/app-config")
def admin_get_app_config(x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)
    cfg = _get_config()
    return {
        "force_update": cfg.get("force_update") == "1",
        "block_all": cfg.get("block_all") == "1",
        "min_version": cfg.get("min_version") or "1.0.0",
        "latest_version": cfg.get("latest_version") or "1.0.0",
        "update_message": cfg.get("update_message") or "",
        "update_url": cfg.get("update_url") or "",
        "update_sha256": cfg.get("update_sha256") or "",
        "block_message": cfg.get("block_message") or "",
    }


@app.post("/admin/force-update")
def admin_force_update(data: ForceUpdateRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    updates = {}
    if data.force_update is not None:
        updates["force_update"] = "1" if data.force_update else "0"
    if data.block_all is not None:
        updates["block_all"] = "1" if data.block_all else "0"
    if data.min_version is not None:
        updates["min_version"] = data.min_version.strip()
    if data.latest_version is not None:
        updates["latest_version"] = data.latest_version.strip()
    if data.update_message is not None:
        updates["update_message"] = data.update_message
    if data.update_url is not None:
        updates["update_url"] = data.update_url
    if data.update_sha256 is not None:
        updates["update_sha256"] = data.update_sha256.strip().lower()
    if data.block_message is not None:
        updates["block_message"] = data.block_message

    if not updates:
        raise HTTPException(status_code=400, detail="Нечего обновлять")

    _set_config(updates)
    return {"ok": True, "config": admin_get_app_config(x_admin_secret)}


@app.post("/admin/reset")
def reset_license(data: ResetKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]

    if not keys_list and not data.hwid:
        raise HTTPException(status_code=400, detail="Укажи key / keys или hwid")

    conn = get_db()
    cur = conn.cursor()
    reset_keys = []

    for key in keys_list:
        cur.execute("SELECT key FROM licenses WHERE key = %s", (key,))
        if not cur.fetchone():
            continue
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
        cur.execute("SELECT key FROM licenses WHERE hwid = %s AND used = 1", (hwid,))
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
            if row["key"] not in reset_keys:
                reset_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "reset": reset_keys, "count": len(reset_keys)}


@app.post("/admin/revoke")
def revoke_key(data: RevokeKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]

    if not keys_list and not data.hwid:
        raise HTTPException(status_code=400, detail="Укажи key / keys или hwid")

    conn = get_db()
    cur = conn.cursor()
    revoked_keys = []

    for key in keys_list:
        cur.execute("SELECT key FROM licenses WHERE key = %s", (key,))
        if not cur.fetchone():
            continue
        cur.execute("UPDATE licenses SET revoked = 1 WHERE key = %s", (key,))
        revoked_keys.append(key)

    if data.hwid:
        hwid = data.hwid.strip()
        cur.execute("SELECT key FROM licenses WHERE hwid = %s", (hwid,))
        for row in cur.fetchall():
            cur.execute("UPDATE licenses SET revoked = 1 WHERE key = %s", (row["key"],))
            if row["key"] not in revoked_keys:
                revoked_keys.append(row["key"])

    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "revoked": revoked_keys, "count": len(revoked_keys)}


@app.post("/admin/unrevoke")
def unrevoke_key(data: RevokeKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]
    if not keys_list:
        raise HTTPException(status_code=400, detail="Укажи key или keys")

    conn = get_db()
    cur = conn.cursor()
    done = []
    for key in keys_list:
        cur.execute("UPDATE licenses SET revoked = 0 WHERE key = %s", (key,))
        if cur.rowcount:
            done.append(key)
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "unrevoked": done, "count": len(done)}


@app.post("/admin/delete")
def delete_key(data: DeleteKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]
    if not keys_list:
        raise HTTPException(status_code=400, detail="Укажи key или keys")

    conn = get_db()
    cur = conn.cursor()
    deleted = []
    for key in keys_list:
        cur.execute("DELETE FROM licenses WHERE key = %s RETURNING key", (key,))
        row = cur.fetchone()
        if row:
            deleted.append(row["key"])
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "deleted": deleted, "count": len(deleted)}


@app.post("/admin/add-keys")
def add_keys(data: AddKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    days = data.duration_days or 0
    hours = data.duration_hours or 0
    secs = data.duration_seconds or 0
    total = days * 86400 + hours * 3600 + secs
    duration_seconds = total if total > 0 else None

    note = (data.note or "").strip()[:500]
    batch_id = (data.batch_id or "").strip()[:64]
    if not batch_id and data.count > 1:
        batch_id = secrets.token_hex(6).upper()

    prefix = (data.prefix or "").strip().upper()
    if prefix and not prefix.endswith("-"):
        prefix = prefix + "-"

    key_type = _normalize_key_type(data.key_type)

    conn = get_db()
    cur = conn.cursor()
    created = []
    max_n = max(1, min(int(data.count), 200))

    for _ in range(max_n):
        if data.key:
            key = data.key.strip().upper()
        else:
            key = prefix + _gen_key() if prefix else _gen_key()
        try:
            cur.execute(
                """
                INSERT INTO licenses
                    (key, used, created_at, revoked, duration_seconds, expires_at, note, batch_id, key_type)
                VALUES (%s, 0, %s, 0, %s, NULL, %s, %s, %s)
                """,
                (key, _now().isoformat(), duration_seconds, note, batch_id, key_type),
            )
            created.append({
                "key": key,
                "permanent": duration_seconds is None,
                "duration_seconds": duration_seconds,
                "note": note,
                "batch_id": batch_id,
                "key_type": key_type,
            })
            if data.key:
                break
        except psycopg2.IntegrityError:
            conn.rollback()
            if data.key:
                cur.close()
                conn.close()
                raise HTTPException(status_code=409, detail="Key already exists")
            continue

    conn.commit()
    cur.close()
    conn.close()
    return {
        "created": created,
        "count": len(created),
        "permanent": duration_seconds is None,
        "duration_seconds": duration_seconds,
        "batch_id": batch_id,
        "key_type": key_type,
    }


@app.post("/admin/extend")
def extend_key(data: ExtendKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]
    if not keys_list:
        raise HTTPException(status_code=400, detail="Укажи key или keys")

    if not data.permanent:
        days = data.duration_days or 0
        hours = data.duration_hours or 0
        add_seconds = days * 86400 + hours * 3600
        if add_seconds <= 0:
            raise HTTPException(
                status_code=400,
                detail="Укажи duration_days/duration_hours или permanent=true",
            )
    else:
        add_seconds = 0

    conn = get_db()
    cur = conn.cursor()
    results = []

    for key in keys_list:
        cur.execute("SELECT * FROM licenses WHERE key = %s", (key,))
        row = cur.fetchone()
        if not row:
            results.append({"key": key, "ok": False, "message": "Key not found"})
            continue

        if data.permanent:
            cur.execute(
                "UPDATE licenses SET duration_seconds = NULL, expires_at = NULL, revoked = 0 WHERE key = %s",
                (key,),
            )
            results.append({"key": key, "ok": True, "permanent": True, "expires_at": None})
            continue

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
        results.append({
            "key": key,
            "ok": True,
            "permanent": False,
            "expires_at": new_exp.isoformat(),
            "duration_seconds": duration_seconds,
        })

    conn.commit()
    cur.close()
    conn.close()

    ok_count = sum(1 for r in results if r.get("ok"))
    return {
        "ok": ok_count > 0,
        "results": results,
        "count": ok_count,
        "permanent": data.permanent if ok_count == 1 and len(results) == 1 else None,
        "expires_at": results[0].get("expires_at") if len(results) == 1 else None,
        "key": results[0].get("key") if len(results) == 1 else None,
    }


@app.post("/admin/set-note")
def set_note(data: NoteKeyRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)
    key = data.key.strip().upper()
    note = (data.note or "").strip()[:500]
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE licenses SET note = %s WHERE key = %s RETURNING key", (note, key))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not row:
        return {"ok": False, "message": "Key not found"}
    return {"ok": True, "key": key, "note": note}


@app.post("/admin/set-key-type")
def set_key_type(data: SetKeyTypeRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)

    keys_list = list(data.keys or [])
    if data.key:
        keys_list.append(data.key)
    keys_list = [k.strip().upper() for k in keys_list if k and k.strip()]
    if not keys_list:
        raise HTTPException(status_code=400, detail="Укажи key или keys")

    key_type = _normalize_key_type(data.key_type)

    conn = get_db()
    cur = conn.cursor()
    updated = []
    for key in keys_list:
        cur.execute(
            "UPDATE licenses SET key_type = %s WHERE key = %s RETURNING key",
            (key_type, key),
        )
        row = cur.fetchone()
        if row:
            updated.append(row["key"])
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "updated": updated, "count": len(updated), "key_type": key_type}


@app.get("/admin/list-keys")
def list_keys(
    x_admin_secret: str = Header(...),
    status: Optional[str] = None,
    q: Optional[str] = None,
    batch_id: Optional[str] = None,
    key_type: Optional[str] = None,
    limit: int = 5000,
    offset: int = 0,
):
    _require_admin(x_admin_secret)
    limit = max(1, min(limit, 10000))
    offset = max(0, offset)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT key, used, used_at, created_at, hwid, revoked,
               duration_seconds, expires_at, note, batch_id, key_type
        FROM licenses
        ORDER BY created_at DESC NULLS LAST
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    keys = [_row_to_key(row) for row in rows]

    # Attach Discord accounts reported by clients
    conn2 = get_db()
    cur2 = conn2.cursor()
    acc_map = _accounts_for_keys(cur2, [k["key"] for k in keys])
    cur2.close()
    conn2.close()
    for k in keys:
        k["accounts"] = acc_map.get(k["key"], [])

    if status and status != "all":
        keys = [k for k in keys if k["status"] == status]
    if batch_id:
        bid = batch_id.strip()
        keys = [k for k in keys if (k.get("batch_id") or "") == bid]
    if key_type and key_type.strip().lower() in ("basic", "free", "premium", "free_2d"):
        kt = key_type.strip().lower()
        if kt == "free_2d":
            kt = "free"
        keys = [k for k in keys if (k.get("key_type") or "premium") == kt]
    if q:
        qq = q.strip().lower()
        def _match(k):
            if qq in (k.get("key") or "").lower():
                return True
            if qq in (k.get("hwid") or "").lower():
                return True
            if qq in (k.get("note") or "").lower():
                return True
            if qq in (k.get("batch_id") or "").lower():
                return True
            if qq in (k.get("key_type") or "").lower():
                return True
            for a in k.get("accounts") or []:
                if qq in (a.get("account_name") or "").lower():
                    return True
                if qq in (a.get("account_id") or "").lower():
                    return True
            return False
        keys = [k for k in keys if _match(k)]

    total_filtered = len(keys)
    page = keys[offset: offset + limit]

    all_keys = [_row_to_key(row) for row in rows]
    return {
        "total": len(all_keys),
        "filtered": total_filtered,
        "offset": offset,
        "limit": limit,
        "available": sum(1 for k in all_keys if k["status"] == "available"),
        "used": sum(1 for k in all_keys if k["status"] == "used"),
        "revoked": sum(1 for k in all_keys if k["status"] == "revoked"),
        "expired": sum(1 for k in all_keys if k["status"] == "expired"),
        "basic": sum(1 for k in all_keys if k.get("key_type") == "basic"),
        "free": sum(1 for k in all_keys if k.get("key_type") == "free"),
        "premium": sum(1 for k in all_keys if k.get("key_type") == "premium"),
        "free_2d": sum(1 for k in all_keys if k.get("key_type") == "free"),  # legacy alias
        "keys": page,
    }


@app.get("/admin/stats")
def stats(x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT key, used, revoked, expires_at, duration_seconds,
               created_at, used_at, key_type
        FROM licenses
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    total = len(rows)
    available = used = revoked = expired = permanent = basic = free = premium = 0
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
        if row.get("duration_seconds") is None and row.get("expires_at") is None:
            permanent += 1
        kt = _normalize_key_type(row.get("key_type"))
        if kt == "basic":
            basic += 1
        elif kt == "free":
            free += 1
        else:
            premium += 1

    return {
        "total": total,
        "available": available,
        "used": used,
        "revoked": revoked,
        "expired": expired,
        "permanent": permanent,
        "basic": basic,
        "free": free,
        "premium": premium,
        # legacy aliases for older admin clients
        "free_2d": free,
    }




class ClearFree2dRequest(BaseModel):
    hwid: Optional[str] = None
    key: Optional[str] = None


@app.post("/admin/clear-free-2d")
def clear_free_2d_block(data: ClearFree2dRequest, x_admin_secret: str = Header(...)):
    """Remove Free once-per-HWID lock so the device can activate a Free key again."""
    _require_admin(x_admin_secret)
    hwid = (data.hwid or "").strip()
    key = (data.key or "").strip().upper()
    if not hwid and not key:
        raise HTTPException(status_code=400, detail="Укажи hwid или key")

    conn = get_db()
    cur = conn.cursor()
    removed = []

    if hwid:
        cur.execute(
            "DELETE FROM free_2d_claims WHERE hwid = %s RETURNING hwid, key, claimed_at",
            (hwid,),
        )
        for row in cur.fetchall() or []:
            removed.append({"hwid": row["hwid"], "key": row.get("key"), "claimed_at": row.get("claimed_at")})
    if key:
        cur.execute(
            "DELETE FROM free_2d_claims WHERE key = %s RETURNING hwid, key, claimed_at",
            (key,),
        )
        for row in cur.fetchall() or []:
            item = {"hwid": row["hwid"], "key": row.get("key"), "claimed_at": row.get("claimed_at")}
            if item not in removed:
                removed.append(item)

    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "cleared": removed, "count": len(removed)}


@app.get("/admin/free-2d-claims")
def list_free_2d_claims(x_admin_secret: str = Header(...), limit: int = 500):
    _require_admin(x_admin_secret)
    limit = max(1, min(int(limit), 5000))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT hwid, key, claimed_at
        FROM free_2d_claims
        ORDER BY claimed_at DESC NULLS LAST
        LIMIT %s
        """,
        (limit,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {"claims": [dict(r) for r in rows], "count": len(rows)}

@app.post("/admin/lookup")
def lookup_keys(data: BulkStatusRequest, x_admin_secret: str = Header(...)):
    _require_admin(x_admin_secret)
    wanted = {k.strip().upper() for k in data.keys if k and k.strip()}
    if not wanted:
        return {"keys": []}
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT key, used, used_at, created_at, hwid, revoked,
               duration_seconds, expires_at, note, batch_id, key_type
        FROM licenses WHERE key = ANY(%s)
        """,
        (list(wanted),),
    )
    rows = cur.fetchall()
    result = [_row_to_key(r) for r in rows]
    acc_map = _accounts_for_keys(cur, [k["key"] for k in result])
    for k in result:
        k["accounts"] = acc_map.get(k["key"], [])
    cur.close()
    conn.close()
    return {"keys": result}
