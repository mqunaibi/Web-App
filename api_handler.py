# api_handler.py
# -*- coding: utf-8 -*-
"""
DB interaction and admin/user management layer.
- Uses get_conn() from db.py to centralize DB connectivity.
- Includes a safe fallback connection using .env if db.py is not available.
- Supports legacy password formats and auto-migrates to a modern hash
  method defined via the ADMIN_HASH_METHOD environment variable.
"""

import logging
import os
import re
import hashlib
from typing import Any, Dict, List, Optional, Tuple

import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables early
load_dotenv()

# =========================
# Import get_conn from db.py
# =========================
def _fallback_get_conn():
    """
    Fallback connection directly from .env if db.py is not present yet.
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        charset="utf8mb4",
        cursorclass=DictCursor,
    )

try:
    # Preferred import: a centralized DB connection
    from db import get_conn  # type: ignore
except Exception:
    # If db.py is not created yet, keep the app working using the fallback
    get_conn = _fallback_get_conn  # type: ignore

# =========================
# Password hashing (modern + compatibility)
# =========================
HASH_METHOD = os.getenv("ADMIN_HASH_METHOD", "pbkdf2:sha256")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _is_sha256_hex(s: str) -> bool:
    return bool(s) and bool(HEX64_RE.fullmatch(s.strip()))


def _looks_like_werkzeug_hash(s: str) -> bool:
    """
    Quick heuristic for Werkzeug-compatible hashes (e.g., 'pbkdf2:' or 'scrypt:').
    """
    if not s:
        return False
    s = s.strip().lower()
    return s.startswith("pbkdf2:") or s.startswith("scrypt:")


def _migrate_password_to_modern(admin_id: int, plain_password: str):
    """
    Upgrade password to the modern format specified by HASH_METHOD.
    """
    hashed = generate_password_hash(plain_password, method=HASH_METHOD)
    return execute_query(
        "UPDATE admin_users SET password = %s WHERE id = %s",
        (hashed, admin_id),
    )

# =========================
# DB helpers
# =========================
def execute_query(
    query: str,
    params: Optional[Tuple[Any, ...]] = None,
    fetch: bool = False,
) -> Any:
    """
    Unified query executor.
    - fetch=True returns a list of dict rows.
    - On error, returns a string "DB Error: <details>" (for compatibility).
    """
    conn = None
    result: Any = None
    try:
        conn = get_conn()
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            if fetch:
                result = cursor.fetchall()
            else:
                result = True
        conn.commit()
    except Exception as e:
        logging.exception("✗ Query Error while executing: %s", query)
        result = f"DB Error: {e}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return result

# =========================
# Users (pending / approved / rejected)
# =========================
def get_pending_users():
    return execute_query(
        "SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid "
        "FROM users WHERE approved = 0",
        fetch=True,
    )


def get_approved_users():
    return execute_query(
        "SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid "
        "FROM users WHERE approved = 1",
        fetch=True,
    )


def get_rejected_users():
    return execute_query(
        "SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid "
        "FROM users WHERE approved = -1",
        fetch=True,
    )


def approve_user(email: str):
    logging.warning("Approving user: %s", email)
    return execute_query("UPDATE users SET approved = 1 WHERE email = %s", (email,))


def reject_user(email: str):
    logging.warning("Rejecting user: %s", email)
    return execute_query("UPDATE users SET approved = -1 WHERE email = %s", (email,))


def delete_user(email: str):
    return execute_query("DELETE FROM users WHERE email = %s", (email,))

# =========================
# Admins
# =========================
def get_admin_by_id(admin_id: int) -> Optional[Dict[str, Any]]:
    res = execute_query(
        "SELECT id, username, role, is_active FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True,
    )
    return res[0] if res else None


def get_admin_by_username(username: str) -> Optional[Dict[str, Any]]:
    res = execute_query(
        "SELECT id, username, password, role, is_active FROM admin_users WHERE username = %s",
        (username,),
        fetch=True,
    )
    return res[0] if res else None


def get_all_admins():
    return execute_query(
        "SELECT id, username, role, is_active, created_at FROM admin_users ORDER BY id",
        fetch=True,
    )


def add_admin_user(username: str, password: str, role: str, is_active: int):
    """
    Always store with the modern hashing method (HASH_METHOD).
    """
    hashed = generate_password_hash(password, method=HASH_METHOD)
    return execute_query(
        "INSERT INTO admin_users (username, password, role, is_active, created_at) "
        "VALUES (%s, %s, %s, %s, NOW())",
        (username, hashed, role, is_active),
    )


def update_admin_user(admin_id: int, username: str, role: str, is_active: int):
    return execute_query(
        "UPDATE admin_users SET username = %s, role = %s, is_active = %s WHERE id = %s",
        (username, role, is_active, admin_id),
    )


def delete_admin_user(admin_id: int):
    return execute_query("DELETE FROM admin_users WHERE id = %s", (admin_id,))


def toggle_admin_status(admin_id: int):
    res = execute_query(
        "SELECT is_active FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True,
    )
    if not res:
        return "Admin not found"
    new_status = 0 if res[0]["is_active"] else 1
    return execute_query(
        "UPDATE admin_users SET is_active = %s WHERE id = %s",
        (new_status, admin_id),
    )

# =========================
# Password/auth flows (compatibility + auto-migration)
# =========================
def check_admin_login(username: str, password_plain: str):
    """
    Accepts and verifies:
    - Any Werkzeug-compatible hash (pbkdf2:sha256, scrypt, etc.)
    - Legacy SHA-256 hex
    - Very old plaintext
    Auto-migrates to HASH_METHOD upon first successful legacy verification.
    """
    admin = get_admin_by_username(username)
    if not admin:
        return None, "Invalid username or password"

    stored = (admin.get("password") or "").strip()
    ok = False
    migrated = False

    # 1) Werkzeug-compatible hash
    try:
        ok = check_password_hash(stored, password_plain)
    except Exception:
        ok = False

    # 2) Legacy SHA-256 hex
    if not ok and _is_sha256_hex(stored):
        ok = (_sha256_hex(password_plain) == stored)
        if ok:
            _migrate_password_to_modern(admin["id"], password_plain)
            migrated = True

    # 3) Very old plaintext
    if not ok and not _looks_like_werkzeug_hash(stored) and not _is_sha256_hex(stored):
        ok = (password_plain == stored)
        if ok:
            _migrate_password_to_modern(admin["id"], password_plain)
            migrated = True

    if not ok:
        return None, "Invalid username or password"

    if not admin.get("is_active", 0):
        return None, "Account is inactive"

    if migrated:
        logging.info(
            "Password migrated to modern hash (%s) for user %s (id=%s)",
            HASH_METHOD,
            admin["username"],
            admin["id"],
        )

    return admin, None


def verify_admin_password(admin_id: int, current_password: str) -> bool:
    res = execute_query(
        "SELECT password FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True,
    )
    if not res:
        return False

    stored = (res[0].get("password") or "").strip()

    # 1) Werkzeug hash
    try:
        ok = check_password_hash(stored, current_password)
    except Exception:
        ok = False
    if ok:
        return True

    # 2) Legacy SHA-256
    if _is_sha256_hex(stored):
        ok = (_sha256_hex(current_password) == stored)
        if ok:
            _migrate_password_to_modern(admin_id, current_password)
        return ok

    # 3) Plaintext
    if not _looks_like_werkzeug_hash(stored) and not _is_sha256_hex(stored):
        ok = (current_password == stored)
        if ok:
            _migrate_password_to_modern(admin_id, current_password)
        return ok

    return False


def update_admin_password(admin_id: int, new_password: str):
    """
    Always store with the modern hashing method (HASH_METHOD).
    """
    hashed = generate_password_hash(new_password, method=HASH_METHOD)
    return execute_query(
        "UPDATE admin_users SET password = %s WHERE id = %s",
        (hashed, admin_id),
    )

# =========================
# Activity Log
# =========================
def log_admin_action(username: str, action: str, details: str = "", ip: str = "") -> bool:
    """
    Insert an admin action into admin_activity_log.
    """
    query = """
        INSERT INTO admin_activity_log (admin_username, action, details, ip_address)
        VALUES (%s, %s, %s, %s)
    """
    try:
        execute_query(query, (username, action, details, ip))
        return True
    except Exception as e:
        logging.error("Error logging admin action: %s", e)
        return False
