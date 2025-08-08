from flask import (
    Blueprint, render_template, session, redirect, url_for,
    request, jsonify, flash, abort, g
)
from functools import wraps

from api_handler import (
    get_pending_users, get_approved_users, get_rejected_users,
    approve_user, reject_user, delete_user, add_admin_user
)

newadmin_bp = Blueprint("newadmin", __name__, url_prefix="")

# ------------------------------
# Helpers: role-based authorization (with normalization)
# ------------------------------
def _normalize_role(value, default="limited"):
    """Trim + lowercase for consistent comparisons."""
    return (value if value is not None else default).strip().lower()

def roles_required(*allowed_roles):
    """
    Decorator to protect routes by role.
    - Requires user to be logged in.
    - Allows only roles listed in `allowed_roles` (normalized).
    """
    normalized_allowed = { _normalize_role(r, "") for r in allowed_roles }

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                return redirect(url_for("login"))
            role = _normalize_role(session.get("admin_role"))
            if role not in normalized_allowed:
                abort(403)  # Forbidden
            # Expose role to request/template contexts
            g.admin_role = role
            return f(*args, **kwargs)
        return wrapper
    return decorator


@newadmin_bp.before_request
def _enforce_login_and_context():
    """
    Enforce login for all blueprint routes.
    Also prime g.admin_role (normalized) for templates.
    """
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    g.admin_role = _normalize_role(session.get("admin_role"))


@newadmin_bp.app_context_processor
def inject_role():
    """Inject the current admin role into all templates as `admin_role` (normalized)."""
    return {"admin_role": _normalize_role(session.get("admin_role"))}


# ------------------------------
# Dashboard (landing)
# ------------------------------
@newadmin_bp.route("/admin-dashboard")
def admin_dashboard():
    # أي أدمن مسجّل دخول
    return render_template("dashboard.html")


# ------------------------------
# Users page — super + limited + viewer (viewer = عرض فقط)
# ------------------------------
@newadmin_bp.route("/newadmin")
@roles_required("super", "limited", "viewer")
def newadmin_page():
    # نعرض العدّادات، والجدول يُحمّل عبر AJAX
    pending_users = get_pending_users() or []
    approved_users = get_approved_users() or []
    rejected_users = get_rejected_users() or []

    return render_template(
        "newadmin.html",
        pending_count=len(pending_users),
        approved_count=len(approved_users),
        rejected_count=len(rejected_users),
    )


# ------------------------------
# Users data (JSON) — super + limited + viewer
# ------------------------------
@newadmin_bp.route("/newadmin_data")
@roles_required("super", "limited", "viewer")
def admin_data():
    return jsonify({
        "pending_users": format_users(get_pending_users() or []),
        "approved_users": format_users(get_approved_users() or []),
        "rejected_users": format_users(get_rejected_users() or [])
    })


# ------------------------------
# Sensitive actions — super + limited (viewer ممنوع)
# ------------------------------
@newadmin_bp.route("/newapprove/<email>", methods=["POST"])
@roles_required("super", "limited")
def newapprove(email):
    result = approve_user(email)
    ok = (result is True)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


@newadmin_bp.route("/newreject/<email>", methods=["POST"])
@roles_required("super", "limited")
def newreject(email):
    result = reject_user(email)
    ok = (result is True)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


@newadmin_bp.route("/newdelete_user/<email>", methods=["POST", "DELETE"])
@roles_required("super", "limited")
def newdelete_user(email):
    result = delete_user(email)
    ok = (result is True)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


# ------------------------------
# Admin add (manage admins) — super only
# ------------------------------
@newadmin_bp.route("/admin-add", methods=["GET", "POST"])
@roles_required("super")
def admin_add():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = (request.form.get("role", "viewer") or "viewer").strip().lower()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        result = add_admin_user(username, password, role, is_active)
        if result is True:
            flash("Admin added successfully!", "success")
            return redirect(url_for("admin_manage"))
        else:
            flash(str(result), "danger")

    return render_template("admin_add.html")


# ------------------------------
# Utils
# ------------------------------
def format_users(users):
    return [
        {
            "email": u.get("email"),
            "phone": u.get("phone"),
            "device_name": u.get("device_name", "N/A"),
            "device_type": u.get("device_type", "N/A"),
            "ip_address": u.get("ip_address", "N/A"),
            "registered_at": u.get("created_at", "N/A"),
            "device_uuid": u.get("device_uuid", "N/A"),
        }
        for u in users
    ]
