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
from dotenv import load_dotenv
import os

from newadmin import newadmin_bp
from api_handler import (
    execute_query,
    get_admin_by_id,
    update_admin_user,
    delete_admin_user,
    toggle_admin_status,
    get_all_admins,
    check_admin_login,               # DB-based login
    verify_admin_password,           # NEW
    update_admin_password,           # NEW
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me")
app.register_blueprint(newadmin_bp)


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
            session["admin_role"] = (admin["role"] or "").strip().lower()  # super | limited | viewer
            session["admin_id"] = admin["id"]
            return redirect(url_for("newadmin.admin_dashboard"))
        else:
            error = err or "Login failed"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template("index.html")


@app.after_request
def add_cache_control(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response


# ---------------- Helpers ----------------
def require_roles(*roles):
    """
    Ensure the current admin is logged in AND has one of the allowed roles.
    Returns a redirect to /login if not logged in; raises 403 if role is not allowed.
    """
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    role = (session.get("admin_role", "") or "").strip().lower()
    allowed = {(r or "").strip().lower() for r in roles}
    if role not in allowed:
        abort(403)
    return None


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

        # 1) Update basic fields
        result = update_admin_user(admin_id, username, role, is_active)
        if result is not True:
            flash(f"Error: {result}", "danger")
            return render_template("admin_edit.html", admin=admin)

        # 2) If a new password was provided, update it
        if new_password:
            pw_res = update_admin_password(admin_id, new_password)
            if pw_res is not True:
                flash(f"Error updating password: {pw_res}", "danger")
                return render_template("admin_edit.html", admin=admin)

        flash("Admin updated successfully!", "success")
        return redirect(url_for("admin_manage"))

    return render_template("admin_edit.html", admin=admin)


@app.route("/admin-delete/<int:admin_id>", methods=["POST", "GET"])
def admin_delete(admin_id):
    guard = require_roles("super")
    if guard:
        return guard

    result = delete_admin_user(admin_id)
    if result is True:
        flash("Admin deleted successfully!", "success")
    else:
        flash(f"Error deleting admin: {result}", "danger")
    return redirect(url_for("admin_manage"))


@app.route("/admin-toggle/<int:admin_id>", methods=["POST", "GET"])
def admin_toggle(admin_id):
    guard = require_roles("super")
    if guard:
        return guard

    result = toggle_admin_status(admin_id)
    if result is True:
        flash("Admin status updated.", "success")
    else:
        flash(f"Error updating status: {result}", "danger")
    return redirect(url_for("admin_manage"))


# ---------------- Change password (self-service) ----------------
@app.route("/admin-change-password", methods=["GET", "POST"])
def admin_change_password():
    # Logged-in admins only
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

@app.route("/admin-reset-password/<int:admin_id>", methods=["POST"])
def admin_reset_password(admin_id):
    guard = require_roles("super")
    if guard:
        return guard  # يعيد توجيه/403 إذا ليس Super

    new_password = (request.form.get("new_password") or "").strip()
    confirm = (request.form.get("confirm_password") or "").strip()

    if not new_password or len(new_password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
    if new_password != confirm:
        return jsonify({"ok": False, "error": "Passwords do not match."}), 400

    res = update_admin_password(admin_id, new_password)
    if res is True:
        return jsonify({"ok": True, "message": "Password updated successfully."})
    return jsonify({"ok": False, "error": str(res)}), 500

if __name__ == "__main__":
    app.run(debug=True)
