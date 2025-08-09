import logging
import os
import re
import hashlib
import pymysql
from dotenv import load_dotenv

# Hashing (حديث) + توافق قديم
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# اختر خوارزمية التخزين الحديثة بشكل صريح (متسق دائماً)
HASH_METHOD = os.getenv("ADMIN_HASH_METHOD", "pbkdf2:sha256")

# =========================
# DB helpers
# =========================
def get_db_connection():
    try:
        return pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
        )
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


# =========================
# Hashing compatibility
# =========================
HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def _is_sha256_hex(s: str) -> bool:
    return bool(s) and bool(HEX64_RE.fullmatch(s.strip()))

def _looks_like_werkzeug_hash(s: str) -> bool:
    """أي هاش مدعوم من Werkzeug: يبدأ عادة بـ 'pbkdf2:' أو 'scrypt:' إلخ."""
    if not s:
        return False
    s = s.strip().lower()
    return s.startswith("pbkdf2:") or s.startswith("scrypt:")

def _migrate_password_to_modern(admin_id: int, plain_password: str):
    """ترقية كلمة المرور إلى الصيغة الحديثة المحددة في HASH_METHOD."""
    hashed = generate_password_hash(plain_password, method=HASH_METHOD)
    return execute_query(
        "UPDATE admin_users SET password = %s WHERE id = %s",
        (hashed, admin_id),
    )


# =========================
# Users (pending/approved/rejected)
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

def approve_user(email):
    logging.warning(f"approving user: {email}")
    return execute_query("UPDATE users SET approved = 1 WHERE email = %s", (email,))

def reject_user(email):
    logging.warning(f"rejecting user: {email}")
    return execute_query("UPDATE users SET approved = -1 WHERE email = %s", (email,))

def delete_user(email):
    return execute_query("DELETE FROM users WHERE email = %s", (email,))


# =========================
# Admins
# =========================
def get_admin_by_id(admin_id):
    res = execute_query(
        "SELECT id, username, role, is_active FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True,
    )
    return res[0] if res else None

def get_admin_by_username(username: str):
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

def add_admin_user(username, password, role, is_active):
    """خزّن دائمًا بصيغة حديثة ومحددة (HASH_METHOD)."""
    hashed = generate_password_hash(password, method=HASH_METHOD)
    return execute_query(
        "INSERT INTO admin_users (username, password, role, is_active, created_at) "
        "VALUES (%s, %s, %s, %s, NOW())",
        (username, hashed, role, is_active),
    )

def update_admin_user(admin_id, username, role, is_active):
    return execute_query(
        "UPDATE admin_users SET username = %s, role = %s, is_active = %s WHERE id = %s",
        (username, role, is_active, admin_id),
    )

def delete_admin_user(admin_id):
    return execute_query("DELETE FROM admin_users WHERE id = %s", (admin_id,))

def toggle_admin_status(admin_id):
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
# Password flows (توافق + ترقية تلقائية)
# =========================
def check_admin_login(username: str, password_plain: str):
    """
    يدعم الصيغ:
      - أي هاش Werkzeug (pbkdf2:sha256 أو scrypt …)
      - SHA-256 hex القديم
      - plaintext القديم جداً
    ويُهاجر تلقائيًا إلى HASH_METHOD عند أول نجاح.
    """
    admin = get_admin_by_username(username)
    if not admin:
        return None, "Invalid username or password"

    stored = (admin.get("password") or "").strip()
    ok = False
    migrated = False

    # 1) حاول مباشرةً مع check_password_hash (يدعم scrypt/pbkdf2..)
    try:
        ok = check_password_hash(stored, password_plain)
    except Exception:
        ok = False

    # 2) لو فشل، افحص SHA-256 hex
    if not ok and _is_sha256_hex(stored):
        ok = (_sha256_hex(password_plain) == stored)
        if ok:
            _migrate_password_to_modern(admin["id"], password_plain); migrated = True

    # 3) لو فشل، افحص plaintext قديم
    if not ok and not _looks_like_werkzeug_hash(stored) and not _is_sha256_hex(stored):
        ok = (password_plain == stored)
        if ok:
            _migrate_password_to_modern(admin["id"], password_plain); migrated = True

    if not ok:
        return None, "Invalid username or password"
    if not admin.get("is_active", 0):
        return None, "Account is inactive"

    if migrated:
        logging.info("Password migrated to modern hash (%s) for user %s (id=%s)",
                     HASH_METHOD, admin["username"], admin["id"])

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

    # 1) حاول مباشرةً مع check_password_hash
    try:
        ok = check_password_hash(stored, current_password)
    except Exception:
        ok = False
    if ok:
        return True

    # 2) SHA-256
    if _is_sha256_hex(stored):
        ok = (_sha256_hex(current_password) == stored)
        if ok:
            _migrate_password_to_modern(admin_id, current_password)
        return ok

    # 3) plaintext
    if not _looks_like_werkzeug_hash(stored) and not _is_sha256_hex(stored):
        ok = (current_password == stored)
        if ok:
            _migrate_password_to_modern(admin_id, current_password)
        return ok

    return False


def update_admin_password(admin_id: int, new_password: str):
    """اكتب دائمًا بصيغة حديثة محددة (HASH_METHOD)."""
    hashed = generate_password_hash(new_password, method=HASH_METHOD)
    return execute_query(
        "UPDATE admin_users SET password = %s WHERE id = %s",
        (hashed, admin_id),
    )

def log_admin_action(username, action, details="", ip=""):
    """
    سجل عملية مشرف في جدول admin_activity_log
    """
    query = """
        INSERT INTO admin_activity_log (admin_username, action, details, ip_address)
        VALUES (%s, %s, %s, %s)
    """
    try:
        execute_query(query, (username, action, details, ip))
        return True
    except Exception as e:
        print(f"Error logging admin action: {e}")
        return False
