import logging
import pymysql
import os
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env in project root
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


def get_db_connection():
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
        )
        print("✓ Connected to MariaDB")
        return conn
    except pymysql.MySQLError as e:
        print(f"✗ Connection Error: {e}")
        return None


def execute_query(query, params=None, fetch=False):
    conn = get_db_connection()
    result = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            if fetch:
                result = cursor.fetchall()
            else:
                result = True
        conn.commit()
    except Exception as e:
        print(f"✗ Query Error: {e}")
        result = f"DB Error: {e}"
    finally:
        if conn:
            conn.close()
    return result


# ========= Helpers (Hashing) =========
def _sha256_hex(s: str) -> str:
    """Return SHA-256 hex digest for a given string."""
    return hashlib.sha256(s.encode()).hexdigest()


# --- Users (pending/approved/rejected) ---
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


def approve_user(email):
    logging.warning(f"approving user: {email}")
    return execute_query("UPDATE users SET approved = 1 WHERE email = %s", (email,))


def reject_user(email):
    logging.warning(f"rejecting user: {email}")
    return execute_query("UPDATE users SET approved = -1 WHERE email = %s", (email,))


def delete_user(email):
    return execute_query("DELETE FROM users WHERE email = %s", (email,))


# --- Admins ---
def get_admin_by_id(admin_id):
    result = execute_query(
        "SELECT id, username, role, is_active FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True,
    )
    return result[0] if result else None


def update_admin_user(admin_id, username, role, is_active):
    return execute_query(
        "UPDATE admin_users SET username = %s, role = %s, is_active = %s WHERE id = %s",
        (username, role, is_active, admin_id),
    )


def delete_admin_user(admin_id):
    return execute_query("DELETE FROM admin_users WHERE id = %s", (admin_id,))


def toggle_admin_status(admin_id):
    result = execute_query(
        "SELECT is_active FROM admin_users WHERE id = %s", (admin_id,), fetch=True
    )
    if not result:
        return "Admin not found"
    current_status = result[0]["is_active"]
    new_status = 0 if current_status else 1
    return execute_query(
        "UPDATE admin_users SET is_active = %s WHERE id = %s",
        (new_status, admin_id),
    )


def get_all_admins():
    return execute_query(
        "SELECT id, username, role, is_active, created_at FROM admin_users",
        fetch=True,
    )


def add_admin_user(username, password, role, is_active):
    hashed = _sha256_hex(password)
    return execute_query(
        "INSERT INTO admin_users (username, password, role, is_active, created_at) "
        "VALUES (%s, %s, %s, %s, NOW())",
        (username, hashed, role, is_active),
    )


# --- Password change for admins (NEW) ---
def verify_admin_password(admin_id: int, current_password: str) -> bool:
    """
    Return True if current_password matches the admin's stored password.
    """
    hashed = _sha256_hex(current_password)
    res = execute_query(
        "SELECT id FROM admin_users WHERE id = %s AND password = %s",
        (admin_id, hashed),
        fetch=True,
    )
    return bool(res)


def update_admin_password(admin_id: int, new_password: str):
    """
    Update admin password using SHA-256 hex. Returns True or 'DB Error: ...'
    """
    hashed = _sha256_hex(new_password)
    return execute_query(
        "UPDATE admin_users SET password = %s WHERE id = %s",
        (hashed, admin_id),
    )


# --- DB-based login helpers ---
def get_admin_by_username(username: str):
    result = execute_query(
        "SELECT id, username, password, role, is_active FROM admin_users WHERE username = %s",
        (username,),
        fetch=True,
    )
    return result[0] if result else None


def check_admin_login(username: str, password_plain: str):
    """
    Return (admin_dict, None) on success, or (None, error_message) on failure.
    """
    admin = get_admin_by_username(username)
    if not admin:
        return None, "Invalid username or password"
    hashed = _sha256_hex(password_plain)
    if admin["password"] != hashed:
        return None, "Invalid username or password"
    if not admin.get("is_active", 0):
        return None, "Account is inactive"
    return admin, None
