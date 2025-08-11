# app.py
# -*- coding: utf-8 -*-
"""
Main Flask application entrypoint.
- Loads environment variables from .env
- Configures Flask secret key and secure session cookies
- Uses ProxyFix for correct client IPs behind reverse proxies
- Provides /login and /logout routes
- Registers the newadmin blueprint (admin pages)
- Preserves existing behaviors and routes
"""
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.mime.text import MIMEText

import os
import sys
import logging
from datetime import timedelta
from notify import notify_new_user_request

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
    abort,
)
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from newadmin import newadmin_bp
from api_handler import (
    execute_query,
    get_admin_by_id,
    update_admin_user,
    delete_admin_user,
    toggle_admin_status,
    get_all_admins,
    check_admin_login,
    verify_admin_password,
    update_admin_password,
    # DB activity log
    log_admin_action,
    # NEW: pending notify helpers
    get_users_pending_email_notifications,
    mark_user_email_notified,    get_admin_by_email,
)

from auth_utils import require_roles

# ---- Load .env early ----
load_dotenv()

PASSWORD_RESET_SALT = os.getenv("PASSWORD_RESET_SALT", "pw-reset-salt")
PASSWORD_RESET_EXP_SECONDS = int(os.getenv("PASSWORD_RESET_EXP_SECONDS", "3600"))  # 1 hour
ADMIN_PANEL_URL = os.getenv("ADMIN_PANEL_URL", "").rstrip("/")

def _get_serializer():
    secret = os.getenv("SECRET_KEY", "change-me")
    return URLSafeTimedSerializer(secret_key=secret, salt=PASSWORD_RESET_SALT)

def _absolute_url(path: str) -> str:
    # 
    base = ADMIN_PANEL_URL or (request.url_root.rstrip("/"))
    return f"{base}{path}"

def _send_email(to_email: str, subject: str, html: str):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASSWORD")
    use_tls = os.getenv("SMTP_USE_TLS", "1") == "1"
    use_ssl = os.getenv("SMTP_USE_SSL", "0") == "1"
    from_email = os.getenv("NOTIFY_FROM", user)

    if not (host and port and user and pwd and from_email):
        app.logger.error("SMTP is not configured properly.")
        return False, "SMTP misconfiguration"

    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port)
        else:
            server = smtplib.SMTP(host, port)
        server.ehlo()
        if use_tls and not use_ssl:
            server.starttls()
        server.login(user, pwd)
        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()
        return True, None
    except Exception as e:
        app.logger.exception("Send email failed: %s", e)
        return False, str(e)


# ---- Logging: file + console ----
log_format = "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(message)s"
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format=log_format,
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me")

# ---- Let Flask trust proxy headers (X-Forwarded-For) ----
# So request.remote_addr becomes the client IP when behind Nginx/Gunicorn
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ---- Session security (no behavior change) ----
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "1") == "1",
)

# If you prefer an explicit lifetime, uncomment the next line:
# app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# Register blueprints
app.register_blueprint(newadmin_bp)

# -------- Helper: reliable client IP ----------
def get_client_ip() -> str:
    """
    Returns the real client IP, honoring X-Forwarded-For / X-Real-IP
    when running behind a reverse proxy (Nginx).
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri.strip()
    return request.remote_addr or ""

# ---------------- Auth ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin, err = check_admin_login(username, password)
        if admin:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_user"] = admin["username"]
            session["admin_role"] = (admin["role"] or "").strip().lower()
            session["admin_id"] = admin["id"]
            # DB log (best-effort)
            try:
                log_admin_action(
                    admin["username"], "login", "Admin logged in", get_client_ip()
                )
            except Exception as e:
                app.logger.warning("DB log (login) failed for %s: %s", admin["username"], e)
            return redirect(url_for("newadmin.admin_dashboard"))
        else:
            error = err or "Login failed"
    return render_template("login.html", error=error)



# ---------------- Forgot / Reset password (self-service by email) ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        admin = None
        try:
            admin = get_admin_by_email(email)
        except Exception as e:
            app.logger.warning("get_admin_by_email error for %s: %s", email, e)

        # Do not reveal whether email exists (privacy & security)
        try:
            if admin:
                s = _get_serializer()
                token = s.dumps({"admin_id": admin["id"], "email": email})
                reset_link = url_for("reset_password", token=token, _external=True)
                html = f"""
                <p>You requested to reset your password.</p>
                <p>To proceed, click the link below (valid for 1 hour):</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
                <p>If you did not request this, you can safely ignore this email.</p>
                """
                ok, err = _send_email(email, "Password reset link", html)
                if not ok:
                    app.logger.error("Password reset email failed for %s: %s", email, err)
        except Exception as e:
            app.logger.exception("forgot-password failed: %s", e)

        message = "If the email is registered, a password reset link has been sent."
        return render_template("forgot_password.html", message=message)

    return render_template("forgot_password.html", message=message)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    error = None
    message = None
    show_form = True
    token = request.values.get("token", "")

    if request.method == "GET":
        try:
            s = _get_serializer()
            s.loads(token, max_age=PASSWORD_RESET_EXP_SECONDS)  # validate only
            return render_template("reset_password.html", token=token, show_form=True)
        except SignatureExpired:
            error = "The reset link has expired. Please request a new one."
            show_form = False
        except BadSignature:
            error = "Invalid reset link."
            show_form = False
        return render_template("reset_password.html", error=error, show_form=show_form)

    # POST — save new password
    new_password = (request.form.get("new_password") or "").strip()
    confirm = (request.form.get("confirm_password") or "").strip()
    if len(new_password) < 8:
        return render_template("reset_password.html", token=token, error="Minimum 8 characters.", show_form=True)
    if new_password != confirm:
        return render_template("reset_password.html", token=token, error="Passwords do not match.", show_form=True)

    try:
        s = _get_serializer()
        data = s.loads(token, max_age=PASSWORD_RESET_EXP_SECONDS)
        admin_id = data.get("admin_id")
        if not admin_id:
            raise BadSignature("missing id")

        ok = update_admin_password(admin_id, new_password)
        if ok is True:
            message = "Your new password has been set successfully. You can log in now."
            show_form = False
        else:
            error = f"{ok}"
    except SignatureExpired:
        error = "The reset link has expired. Please request a new one."
        show_form = False
    except BadSignature:
        error = "Invalid reset link."
        show_form = False
    except Exception as e:
        app.logger.exception("reset-password failed: %s", e)
        error = "An unexpected error occurred."

    return render_template("reset_password.html", token=token, message=message, error=error, show_form=show_form)



@app.route("/logout")
def logout():
    who = session.get("admin_user")
    try:
        if who:
            log_admin_action(who, "logout", "Admin logged out", get_client_ip())
    except Exception as e:
        app.logger.warning("DB log (logout) failed for %s: %s", who, e)
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("index.html")

# ---------------- Response headers ----------------
@app.after_request
def add_cache_control(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")

    if (response.mimetype == "text/html") and ("charset" not in (response.content_type or "").lower()):
        response.headers["Content-Type"] = "text/html; charset=utf-8"

    response.headers.pop("Expires", None)
    return response

# ---------------- Admin management (Super only) ----------------
@app.route("/admin-manage")
def admin_manage():
    guard = require_roles("super")
    if guard:
        return guard
    admins = get_all_admins() or []
    return render_template("admin_manage.html", admins=admins)

@app.route("/admin-edit/<int:admin_id>", methods=["GET", "POST"])
def admin_edit(admin_id):
    guard = require_roles("super")
    if guard:
        return guard

    admin = get_admin_by_id(admin_id)
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for("admin_manage"))

    if request.method == "POST":
        username = request.form.get("username") or admin["username"]
        email = (request.form.get("email") or admin.get("email") or "").strip()  # NEW
        role = (request.form.get("role") or admin["role"]).strip().lower()
        raw_active = request.form.get("is_active")
        is_active = 1 if str(raw_active).strip().lower() in ("on", "1", "true", "yes") else 0

        new_password = (request.form.get("new_password") or "").strip()

        app.logger.info(
            "Admin edit requested by super=%s for admin_id=%s (username=%s, email=%s, role=%s, active=%s)",
            session.get("admin_user"),
            admin_id,
            username,
            email,
            role,
            is_active,
        )

        result = update_admin_user(admin_id, username, role, is_active, email)  # UPDATED
        if result is not True:
            app.logger.error(
                "Admin edit failed for id=%s by super=%s: %s",
                admin_id,
                session.get("admin_user"),
                result,
            )
            flash(f"Error: {result}", "danger")
            return render_template("admin_edit.html", admin=admin)

        # DB log: edit admin
        try:
            log_admin_action(
                session.get("admin_user"),
                "edit_admin",
                f"Edited admin id={admin_id} (username={username}, email={email}, role={role}, active={is_active})",
                get_client_ip(),
            )
        except Exception as e:
            app.logger.warning("DB log (edit_admin) failed: %s", e)

        if new_password:
            pw_res = update_admin_password(admin_id, new_password)
            if pw_res is not True:
                app.logger.error(
                    "Password update failed for admin_id=%s by super=%s: %s",
                    admin_id,
                    session.get("admin_user"),
                    pw_res,
                )
                flash(f"Error updating password: {pw_res}", "danger")
                return render_template("admin_edit.html", admin=admin)
            else:
                app.logger.info(
                    "Password updated for admin_id=%s by super=%s",
                    admin_id,
                    session.get("admin_user"),
                )
                # DB log: update admin password
                try:
                    log_admin_action(
                        session.get("admin_user"),
                        "update_admin_password",
                        f"Updated password for admin id={admin_id}",
                        get_client_ip(),
                    )
                except Exception as e:
                    app.logger.warning("DB log (update_admin_password) failed: %s", e)

        app.logger.info(
            "Admin updated successfully: id=%s by super=%s",
            admin_id,
            session.get("admin_user"),
        )
        flash("Admin updated successfully!", "success")
        return redirect(url_for("admin_manage"))

    return render_template("admin_edit.html", admin=admin)

@app.route("/admin-delete/<int:admin_id>", methods=["POST", "GET"])
def admin_delete(admin_id):
    guard = require_roles("super")
    if guard:
        return guard

    app.logger.info(
        "Admin delete requested by super=%s for admin_id=%s",
        session.get("admin_user"),
        admin_id,
    )
    result = delete_admin_user(admin_id)
    if result is True:
        app.logger.info(
            "Admin deleted successfully: id=%s by super=%s",
            admin_id,
            session.get("admin_user"),
        )
        # DB log: delete admin
        try:
            log_admin_action(
                session.get("admin_user"),
                "delete_admin",
                f"Deleted admin id={admin_id}",
                get_client_ip(),
            )
        except Exception as e:
            app.logger.warning("DB log (delete_admin) failed: %s", e)

        flash("Admin deleted successfully!", "success")
    else:
        app.logger.error(
            "Admin delete failed for id=%s by super=%s: %s",
            admin_id,
            session.get("admin_user"),
            result,
        )
        flash(f"Error deleting admin: {result}", "danger")
    return redirect(url_for("admin_manage"))

@app.route("/admin-toggle/<int:admin_id>", methods=["POST", "GET"])
def admin_toggle(admin_id):
    guard = require_roles("super")
    if guard:
        return guard

    app.logger.info(
        "Admin status toggle requested by super=%s for admin_id=%s",
        session.get("admin_user"),
        admin_id,
    )
    result = toggle_admin_status(admin_id)
    if result is True:
        app.logger.info(
            "Admin status toggled successfully: id=%s by super=%s",
            admin_id,
            session.get("admin_user"),
        )
        # DB log: toggle admin status
        try:
            log_admin_action(
                session.get("admin_user"),
                "toggle_admin_status",
                f"Toggled status for admin id={admin_id}",
                get_client_ip(),
            )
        except Exception as e:
            app.logger.warning("DB log (toggle_admin_status) failed: %s", e)

        flash("Admin status updated.", "success")
    else:
        app.logger.error(
            "Admin status toggle failed for id=%s by super=%s: %s",
            admin_id,
            session.get("admin_user"),
            result,
        )
        flash(f"Error updating status: {result}", "danger")
    return redirect(url_for("admin_manage"))

# ---------------- Change password (self-service) ----------------
@app.route("/admin-change-password", methods=["GET", "POST"])
def admin_change_password():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

    msg = None
    err = None

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = (request.form.get("confirm_password") or "").strip()

        if len(new) < 8:
            err = "New password must be at least 8 characters."
        elif new != confirm:
            err = "Passwords do not match."
        elif not verify_admin_password(session.get("admin_id"), current):
            err = "Current password is incorrect."
        else:
            ok = update_admin_password(session.get("admin_id"), new)
            if ok is True:
                msg = "Password updated successfully."
            else:
                err = f"{ok}"

    return render_template("admin_change_password.html", message=msg, error=err)

# ---------------- Pretty error pages ----------------
@app.errorhandler(403)
def handle_forbidden(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def handle_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def handle_internal_error(e):
    return render_template("500.html"), 500

# ---------------- Reset password (by super for any admin) ----------------
@app.route("/admin-reset-password/<int:admin_id>", methods=["POST"])
def admin_reset_password(admin_id):
    if not session.get("admin_logged_in"):
        app.logger.warning("401 reset-password: anonymous tried to reset id=%s", admin_id)
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    role = (session.get("admin_role") or "").strip().lower()
    user = session.get("admin_user")
    if role != "super":
        app.logger.warning("403 reset-password: %s (role=%s) tried to reset id=%s", user, role, admin_id)
        return jsonify({"ok": False, "error": "Forbidden (super only)."}), 403

    try:
        new_password = (request.form.get("new_password") or "").strip()
        confirm = (request.form.get("confirm_password") or "").strip()

        if not new_password or len(new_password) < 8:
            app.logger.warning("Reset password failed (short password) by super=%s for id=%s", user, admin_id)
            return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
        if new_password != confirm:
            app.logger.warning("Reset password failed (mismatch) by super=%s for id=%s", user, role, admin_id)
            return jsonify({"ok": False, "error": "Passwords do not match."}), 400

        res = update_admin_password(admin_id, new_password)
        if res is True:
            app.logger.info("Reset password SUCCESS: id=%s by super=%s", admin_id, user)
            # DB log: reset admin password
            try:
                log_admin_action(
                    user,
                    "reset_admin_password",
                    f"Reset password for admin id={admin_id}",
                    get_client_ip(),
                )
            except Exception as e:
                app.logger.warning("DB log (reset_admin_password) failed: %s", e)

            return jsonify({"ok": True, "message": "Password updated successfully."})

        app.logger.error("DB error on reset password (id=%s) by super=%s: %s", admin_id, user, res)
        return jsonify({"ok": False, "error": str(res)}), 500

    except Exception as e:
        app.logger.exception("Reset password crashed (id=%s) by super=%s: %s", admin_id, user, str(e))
        return jsonify({"ok": False, "error": "Server error"}), 500

# ---------------- Admin logs (JSON API for UI) ----------------
@app.route("/admin-logs-data", methods=["GET"])
def admin_logs_data():
    guard = require_roles("super")
    if guard:
        return guard

    import re
    DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

    # ---- filters ----
    admin = (request.args.get("admin") or "").strip()
    action = (request.args.get("action") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()   # expected: YYYY-MM-DD
    date_to   = (request.args.get("date_to") or "").strip()     # expected: YYYY-MM-DD
    q = (request.args.get("q") or "").strip()

    # validate date format (ignore invalid)
    if date_from and not DATE_RE.match(date_from):
        date_from = ""
    if date_to and not DATE_RE.match(date_to):
        date_to = ""

    # ---- pagination ----
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get("per_page", 20))
        if per_page <= 0 or per_page > 200:
            per_page = 20
    except ValueError:
        per_page = 20
    offset = (page - 1) * per_page

    # ---- WHERE ----
    where_clauses, params = [], []
    if admin:
        where_clauses.append("admin_username = %s"); params.append(admin)
    if action:
        where_clauses.append("action = %s"); params.append(action)
    if date_from:
        where_clauses.append("created_at >= %s"); params.append(f"{date_from} 00:00:00")
    if date_to:
        where_clauses.append("created_at <= %s"); params.append(f"{date_to} 23:59:59")
    if q:
        where_clauses.append("details LIKE %s"); params.append(f"%{q}%")
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        # Count
        count_sql = f"SELECT COUNT(*) AS cnt FROM admin_activity_log{where_sql}"
        total_rows_res = execute_query(count_sql, params, fetch=True) or [{"cnt": 0}]
        total_rows = total_rows_res[0].get("cnt", 0)

        # Page data
        data_sql = (
            "SELECT id, admin_username, action, details, ip_address, created_at "
            f"FROM admin_activity_log{where_sql} "
            "ORDER BY created_at DESC "
            "LIMIT %s OFFSET %s"
        )
        rows = execute_query(data_sql, params + [per_page, offset], fetch=True) or []
        total_pages = (total_rows + per_page - 1) // per_page

        return jsonify({
            "ok": True,
            "items": rows,
            "page": page,
            "per_page": per_page,
            "total": total_rows,
            "total_pages": total_pages,
            "filters": {
                "admin": admin,
                "action": action,
                "date_from": date_from,
                "date_to": date_to,
                "q": q,
            }
        })
    except Exception as e:
        app.logger.exception("admin-logs-data failed: %s", e)
        return jsonify({"ok": False, "error": "Server error while fetching logs."}), 500

# ---------------- Admin logs (page) ----------------
@app.route("/admin-logs", methods=["GET"])
def admin_logs():
    """Renders the admin activity logs page (front-end).
    Data is fetched from /admin-logs-data via fetch in admin_logs.html"""
    guard = require_roles("super")
    if guard:
        return guard

    initial_filters = {
        "admin": (request.args.get("admin") or "").strip(),
        "action": (request.args.get("action") or "").strip(),
        "date_from": (request.args.get("date_from") or "").strip(),  # YYYY-MM-DD
        "date_to": (request.args.get("date_to") or "").strip(),      # YYYY-MM-DD
        "q": (request.args.get("q") or "").strip(),
        "page": int(request.args.get("page", 1) or 1),
        "per_page": int(request.args.get("per_page", 20) or 20),
    }
    return render_template(
        "admin_logs.html",
        initial_filters=initial_filters,
        active_page="logs",
    )

# ---------------- New user request webhook (enhanced) ----------------
# Read once at module import (avoids re-reading env each request)
NOTIFY_INCOMING_TOKEN = os.getenv("NOTIFY_INCOMING_TOKEN", "").strip()
ADMIN_PANEL_URL = os.getenv("ADMIN_PANEL_URL", "/newadmin").strip()

@app.route("/hook/new-user-request", methods=["POST", "GET"])
def hook_new_user_request():
    """
    Secure webhook to trigger the admin email when a new user requests approval.
    GET  -> returns usage (does NOT send email)
    POST -> validates token then sends the notification
    """
    # -------- GET: quick usage for browsers --------
    if request.method == "GET":
        return jsonify({
            "message": "Use POST to send a 'New user approval' notification.",
            "usage": {
                "method": "POST",
                "url": "/hook/new-user-request",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Notify-Token": "<token> (or Authorization: Bearer <token>)"
                },
                "body_example": {
                    "email": "user@example.com",
                    "name": "Full Name",
                    "device_name": "Device model",
                    "device_uuid": "unique-device-id",
                    "extra": {"app_version": "1.0.0", "platform": "Android"}
                }
            }
        })

    # -------- POST: token verification --------
    if not NOTIFY_INCOMING_TOKEN:
        app.logger.error("Webhook refused: NOTIFY_INCOMING_TOKEN not set.")
        return jsonify({"ok": False, "error": "Server not configured"}), 500

    auth_hdr = (request.headers.get("Authorization") or "").strip()
    x_token = (request.headers.get("X-Notify-Token") or "").strip()
    q_token = (request.args.get("token") or "").strip()

    supplied = ""
    if auth_hdr.lower().startswith("bearer "):
        supplied = auth_hdr.split(None, 1)[1].strip()
    elif x_token:
        supplied = x_token
    elif q_token:
        supplied = q_token

    if supplied != NOTIFY_INCOMING_TOKEN:
        app.logger.warning("Webhook unauthorized from %s", get_client_ip())
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    # -------- Read payload --------
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    email = (data.get("email") or "").strip()
    name = (data.get("name") or "").strip()
    device_name = (data.get("device_name") or data.get("device") or "").strip()
    device_uuid = (data.get("device_uuid") or "").strip()
    extra = data.get("extra") or {}

    if not email:
        return jsonify({"ok": False, "error": "Missing 'email'"}), 400

    # client IP behind proxy
    ip_address = get_client_ip()

    # -------- Send email --------
    ok = notify_new_user_request(
        user_email=email,
        user_name=name,
        device_name=device_name,
        device_uuid=device_uuid,
        ip_address=ip_address,
        extra=extra,
        admin_panel_url=ADMIN_PANEL_URL,
    )

    if ok:
        return jsonify({"ok": True, "message": "Notification sent."})
    return jsonify({"ok": False, "error": "Failed to send email"}), 500


# ---------------- Task: notify pending DB registrations ----------------
@app.route("/tasks/notify-pending", methods=["POST", "GET"])
def tasks_notify_pending():
    """
    Processes new pending users (approved=0 & not notified) and sends email notifications.
    GET -> shows usage (no sending)
    POST -> requires TASKS_TOKEN (Bearer or X-Tasks-Token) then processes up to 'limit'
    """
    TASKS_TOKEN = os.getenv("TASKS_TOKEN", "").strip()

    if request.method == "GET":
        return jsonify({
            "message": "Use POST with token to process pending user notifications.",
            "headers": {
                "Authorization": "Bearer <TASKS_TOKEN>",
                "X-Tasks-Token": "<TASKS_TOKEN>",
                "Content-Type": "application/json"
            },
            "body_example": {"limit": 50}
        })

    if not TASKS_TOKEN:
        app.logger.error("TASKS_TOKEN not set")
        return jsonify({"ok": False, "error": "Server not configured"}), 500

    # Token check (Bearer or header or query)
    auth_hdr = (request.headers.get("Authorization") or "").strip()
    x_token = (request.headers.get("X-Tasks-Token") or "").strip()
    q_token = (request.args.get("token") or "").strip()
    supplied = ""
    if auth_hdr.lower().startswith("bearer "):
        supplied = auth_hdr.split(None, 1)[1].strip()
    elif x_token:
        supplied = x_token
    elif q_token:
        supplied = q_token
    if supplied != TASKS_TOKEN:
        app.logger.warning("tasks_notify_pending: unauthorized from %s", get_client_ip())
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    # Optional JSON body
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}
    try:
        limit = int(payload.get("limit", 50))
        if limit <= 0 or limit > 500:
            limit = 50
    except Exception:
        limit = 50

    # Fetch pending users not notified
    rows = get_users_pending_email_notifications(limit=limit) or []
    if not rows or isinstance(rows, str):
        # In case of DB error, rows may be a string
        if isinstance(rows, str):
            app.logger.error("tasks_notify_pending DB error: %s", rows)
            return jsonify({"ok": False, "error": "DB error"}), 500
        return jsonify({"ok": True, "processed": 0, "message": "No pending users to notify"})

    processed = 0
    for u in rows:
        email = (u.get("email") or "").strip()
        if not email:
            continue
        ok = notify_new_user_request(
            user_email=email,
            user_name="",  # name not stored — keep empty
            device_name=u.get("device_name") or "",
            device_uuid=u.get("device_uuid") or "",
            ip_address=u.get("ip_address") or "",
            extra={
                "phone": u.get("phone") or "",
                "device_type": u.get("device_type") or "",
                "registered_at": str(u.get("created_at") or ""),
            },
            admin_panel_url=ADMIN_PANEL_URL,
        )
        if ok:
            mark_user_email_notified(email)
            processed += 1
        else:
            app.logger.error("Email notify failed for user=%s", email)

    return jsonify({"ok": True, "processed": processed})


if __name__ == "__main__":
    app.run(debug=True)
