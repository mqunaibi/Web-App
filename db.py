# db.py
# Unified database connection (MariaDB/MySQL) using PyMySQL.
# Reads settings from .env and exposes get_conn() for other files.

import os
import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv

load_dotenv()

def _get_env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None else default

# Read settings from .env
DB_HOST = _get_env("DB_HOST", "localhost")
DB_NAME = _get_env("DB_NAME", "")
DB_USER = _get_env("DB_USER", "")
DB_PASSWORD = _get_env("DB_PASSWORD", "")
DB_PORT = int(_get_env("DB_PORT", "3306"))

def get_conn() -> pymysql.connections.Connection:
    """
    Returns a new connection on each call.
    Uses DictCursor and utf8mb4 encoding.
    """
    if not (DB_HOST and DB_NAME and DB_USER):
        raise RuntimeError(
            "Database environment variables are missing. "
            "Please set DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD in .env"
        )

    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT,
        charset="utf8mb4",
        cursorclass=DictCursor,
    )
    return conn

def health_check() -> bool:
    """
    Quick check for DB connectivity. Returns True if successful.
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                row = cur.fetchone()
                return bool(row and row.get("ok") == 1)
    except Exception:
        return False
