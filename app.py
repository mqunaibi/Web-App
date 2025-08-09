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
import logging
import sys
from dotenv import load_dotenv
import os

from werkzeug.middleware.proxy_fix import ProxyFix  # NEW

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
)

# unified auth helper
from auth_utils import require_roles

# ---- Load .env early ----
load_dotenv()

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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # NEW

# ---- Session security (no behavior change) ----
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "1") == "1",
)

app.register_blueprint(newadmin_bp)

# -------- Helper: reliable client IP ----------
def get_client_ip() -> str:
    """
    Returns the real client IP, honoring X-Forwarded-For / X-Real-IP
    when running behind a reverse proxy (Nginx).
    """
    # X-Forwarded-For may contain: client, proxy1, proxy2...
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
                log_admin_action(admin["username"], "login", "Admin logged in", get_client_ip())  # CHG
            except Exception as e:
                app.logger.warning("DB log (login) failed for %s: %s", admin["username"], e)
            return redirect(url_for("newadmin.admin_dashboard"))
        else:
            error = err or "Login failed"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    who = session.get("admin_user")
    try:
        if who:
            log_admin_action(who, "logout", "Admin logged out", get_client_ip())  # CHG
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
        role = (request.form.get("role") or admin["role"]).strip().lower()
        is_active = 1 if request.form.get("is_active") == "on" else 0
        new_password = (request.form.get("new_password") or "").strip()

        app.logger.info(
            "Admin edit requested by super=%s for admin_id=%s (username=%s, role=%s, active=%s)",
            session.get("admin_user"),
            admin_id,
            username,
            role,
            is_active,
        )

        result = update_admin_user(admin_id, username, role, is_active)
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
                f"Edited admin id={admin_id} (username={username}, role={role}, active={is_active})",
                get_client_ip(),  # CHG
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
                        get_client_ip(),  # CHG
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
                get_client_ip(),  # CHG
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
                get_client_ip(),  # CHG
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
        confirm = request.form.get("confirm_password", "")

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
            app.logger.warning("Reset password failed (mismatch) by super=%s for id=%s", user, admin_id)
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
                    get_client_ip(),  # CHG
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
    return render_template("admin_logs.html",
                           initial_filters=initial_filters,
                           active_page="logs")

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


if __name__ == "__main__":
    app.run(debug=True)
