import logging
import pymysql
import os
import random
from datetime import datetime
from dotenv import load_dotenv
load_dotenv(dotenv_path="/home/otp/.env")

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
            cursorclass=pymysql.cursors.DictCursor
        )
        print("? Connected to MariaDB")
        return conn
    except pymysql.MySQLError as e:
        print(f"? Connection Error: {e}")
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
        print(f"? Query Error: {e}")
        result = f"DB Error: {e}"
    finally:
        conn.close()
    return result

def get_pending_users():
    return execute_query(
        "SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid FROM users WHERE approved = 0",
        fetch=True
    )

def get_approved_users():
    return execute_query("SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid FROM users WHERE approved = 1", fetch=True)

def get_rejected_users():
    return execute_query("SELECT email, phone, device_name, device_type, ip_address, created_at, device_uuid FROM users WHERE approved = -1", fetch=True)

def approve_user(email):
    logging.warning(f"? approving user: {email}")

    conn = get_db_connection()
    if not conn:
        logging.error("? DB connection failed")
        return "DB connection error"

    try:
        with conn.cursor() as cursor:
            query = "UPDATE users SET approved = 1 WHERE email = %s"
            cursor.execute(query, (email,))
            conn.commit()

            logging.warning(f"?? Rows affected: {cursor.rowcount}")
            if cursor.rowcount == 0:
                return "User not found or already approved"

        return True
    except Exception as e:
        logging.error(f"? DB error: {e}")
        return str(e)
    finally:
        conn.close()

def reject_user(email):
    logging.warning(f"? rejecting user: {email}")
    return execute_query("UPDATE users SET approved = -1 WHERE email = %s", (email,))

def delete_user(email):
    return execute_query("DELETE FROM users WHERE email = %s", (email,))
