from flask import (
    Blueprint, render_template, session, redirect, url_for,
    request, jsonify, flash, abort, g
)
import logging
from auth_utils import roles_required, normalize_role

from api_handler import (
    get_pending_users, get_approved_users, get_rejected_users,
    approve_user, reject_user, delete_user, add_admin_user,
    # ✅ دالة تسجيل الحركات في DB
    log_admin_action,
)

newadmin_bp = Blueprint("newadmin", __name__, url_prefix="")

@newadmin_bp.before_request
def _enforce_login_and_context():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    g.admin_role = normalize_role(session.get("admin_role"))


@newadmin_bp.app_context_processor
def inject_role():
    return {"admin_role": normalize_role(session.get("admin_role"))}


# ------------------------------
# Dashboard (landing)
# ------------------------------
@newadmin_bp.route("/admin-dashboard")
def admin_dashboard():
    return render_template("dashboard.html")


# ------------------------------
# Users page — super + limited + viewer
# ------------------------------
@newadmin_bp.route("/newadmin")
@roles_required("super", "limited", "viewer")
def newadmin_page():
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
# Users data (JSON)
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
# Sensitive actions — with DB logging
# ------------------------------
@newadmin_bp.route("/newapprove/<email>", methods=["POST"])
@roles_required("super", "limited")
def newapprove(email):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Approve request by admin=%s for user=%s", admin_user, email)
    result = approve_user(email)
    ok = (result is True)
    if ok:
        logging.info("User approved: %s by admin=%s", email, admin_user)
        # ✅ Log DB
        try:
            log_admin_action(admin_user, "approve_user", f"Approved user {email}", request.remote_addr)
        except Exception as e:
            logging.warning("DB log (approve_user) failed: %s", e)
    else:
        logging.error("Approve failed for %s by admin=%s: %s", email, admin_user, result)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


@newadmin_bp.route("/newreject/<email>", methods=["POST"])
@roles_required("super", "limited")
def newreject(email):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Reject request by admin=%s for user=%s", admin_user, email)
    result = reject_user(email)
    ok = (result is True)
    if ok:
        logging.info("User rejected: %s by admin=%s", email, admin_user)
        # ✅ Log DB
        try:
            log_admin_action(admin_user, "reject_user", f"Rejected user {email}", request.remote_addr)
        except Exception as e:
            logging.warning("DB log (reject_user) failed: %s", e)
    else:
        logging.error("Reject failed for %s by admin=%s: %s", email, admin_user, result)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


@newadmin_bp.route("/newdelete_user/<email>", methods=["POST", "DELETE"])
@roles_required("super", "limited")
def newdelete_user(email):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Delete request by admin=%s for user=%s", admin_user, email)
    result = delete_user(email)
    ok = (result is True)
    if ok:
        logging.info("User deleted: %s by admin=%s", email, admin_user)
        # ✅ Log DB
        try:
            log_admin_action(admin_user, "delete_user", f"Deleted user {email}", request.remote_addr)
        except Exception as e:
            logging.warning("DB log (delete_user) failed: %s", e)
    else:
        logging.error("Delete failed for %s by admin=%s: %s", email, admin_user, result)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)


# ------------------------------
# Admin add (manage admins)
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
            logging.info("Admin added: %s by super=%s", username, session.get("admin_user", "unknown"))
            # ✅ Log DB
            try:
                log_admin_action(
                    session.get("admin_user"),
                    "add_admin",
                    f"Added admin username={username}, role={role}, active={is_active}",
                    request.remote_addr,
                )
            except Exception as e:
                logging.warning("DB log (add_admin) failed: %s", e)

            flash("Admin added successfully!", "success")
            return redirect(url_for("admin_manage"))
        else:
            logging.error("Failed to add admin=%s by super=%s: %s", username, session.get("admin_user", "unknown"), result)
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
