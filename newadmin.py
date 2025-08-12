# newadmin.py
from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    request,
    jsonify,
    flash,
    g,
)
import logging

from auth_utils import roles_required, normalize_role
from api_handler import (
    get_pending_users,
    get_approved_users,
    get_rejected_users,
    approve_user,
    reject_user,
    delete_user,
    add_admin_user,
    log_admin_action,
)

newadmin_bp = Blueprint("newadmin", __name__, url_prefix="")

# ------------------------------
# Common guards and context
# ------------------------------
@newadmin_bp.before_request
def _enforce_login_and_context():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    g.admin_role = normalize_role(session.get("admin_role"))
    g.admin_company = (session.get("admin_company") or "").strip()

@newadmin_bp.app_context_processor
def inject_role():
    return {
        "admin_role": normalize_role(session.get("admin_role")),
        "admin_company": (session.get("admin_company") or "").strip(),
    }

def _company_filter():
    """
    Return None to disable filtering (see all) when:
      - role is super, OR
      - admin_company equals 'All' (case-insensitive).
    Otherwise return the admin's company.
    """
    role = normalize_role(session.get("admin_role"))
    if role == "super":
        return None
    name = (session.get("admin_company") or "").strip()
    if name.lower() == "all":
        return None
    return name or None

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
    company_name = _company_filter()
    pending_users = get_pending_users(company_name) or []
    approved_users = get_approved_users(company_name) or []
    rejected_users = get_rejected_users(company_name) or []
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
    company_name = _company_filter()
    return jsonify(
        {
            "pending_users": format_users(get_pending_users(company_name) or []),
            "approved_users": format_users(get_approved_users(company_name) or []),
            "rejected_users": format_users(get_rejected_users(company_name) or []),
        }
    )

# ------------------------------
# Sensitive actions — with DB logging
# ------------------------------
@newadmin_bp.route("/newapprove/<string:email>", methods=["POST"])
@roles_required("super", "limited")
def newapprove(email: str):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Approve request by admin=%s for user=%s", admin_user, email)
    result = approve_user(email)
    ok = (result is True)
    if ok:
        logging.info("User approved: %s by admin=%s", email, admin_user)
        try:
            log_admin_action(
                admin_user,
                "approve_user",
                f"Approved user {email}",
                request.remote_addr,
            )
        except Exception as e:
            logging.warning("DB log (approve_user) failed: %s", e)
    else:
        logging.error("Approve failed for %s by admin=%s: %s", email, admin_user, result)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)

@newadmin_bp.route("/newreject/<string:email>", methods=["POST"])
@roles_required("super", "limited")
def newreject(email: str):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Reject request by admin=%s for user=%s", admin_user, email)
    result = reject_user(email)
    ok = (result is True)
    if ok:
        logging.info("User rejected: %s by admin=%s", email, admin_user)
        try:
            log_admin_action(
                admin_user,
                "reject_user",
                f"Rejected user {email}",
                request.remote_addr,
            )
        except Exception as e:
            logging.warning("DB log (reject_user) failed: %s", e)
    else:
        logging.error("Reject failed for %s by admin=%s: %s", email, admin_user, result)
    return jsonify({"success": ok, "message": "OK" if ok else str(result)}), (200 if ok else 400)

@newadmin_bp.route("/newdelete_user/<string:email>", methods=["POST", "DELETE"])
@roles_required("super", "limited")
def newdelete_user(email: str):
    admin_user = session.get("admin_user", "unknown")
    logging.info("Delete request by admin=%s for user=%s", admin_user, email)
    result = delete_user(email)
    ok = (result is True)
    if ok:
        logging.info("User deleted: %s by admin=%s", email, admin_user)
        try:
            log_admin_action(
                admin_user,
                "delete_user",
                f"Deleted user {email}",
                request.remote_addr,
            )
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
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        company_name = (request.form.get("company_name") or "").strip()
        password = request.form.get("password", "")
        role = (request.form.get("role", "viewer") or "viewer").strip().lower()
        is_active = 1 if (request.form.get("is_active") in ("on", "1", "true", "True")) else 0

        # Minimal checks
        if not username:
            flash("Username is required.", "danger")
            return render_template("admin_add.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("admin_add.html")

        # Pass company_name to DB layer
        result = add_admin_user(username, password, role, is_active, email, company_name)

        if result is True:
            logging.info(
                "Admin added: %s by super=%s (email=%s, company=%s, role=%s, active=%s)",
                username,
                session.get("admin_user", "unknown"),
                email,
                company_name,
                role,
                is_active,
            )
            try:
                log_admin_action(
                    session.get("admin_user"),
                    "add_admin",
                    f"Added admin username={username}, email={email}, company={company_name}, role={role}, active={is_active}",
                    request.remote_addr,
                )
            except Exception as e:
                logging.warning("DB log (add_admin) failed: %s", e)

            flash("Admin added successfully!", "success")
            return redirect(url_for("admin_manage"))
        else:
            logging.error(
                "Failed to add admin=%s by super=%s: %s",
                username,
                session.get("admin_user", "unknown"),
                result,
            )
            flash(str(result), "danger")

    return render_template("admin_add.html")

# ------------------------------
# Utils
# ------------------------------
def format_users(users):
    """
    Normalize rows coming from DB (api_handler). The DB column is `company_name`,
    and we expose it to the front-end as `company`.
    """
    return [
        {
            "email": u.get("email"),
            "phone": u.get("phone"),
            "device_name": u.get("device_name", "N/A"),
            "device_type": u.get("device_type", "N/A"),
            "ip_address": u.get("ip_address", "N/A"),
            "registered_at": u.get("created_at", "N/A"),
            "device_uuid": u.get("device_uuid", "N/A"),
            # NEW: expose company name
            "company": (u.get("company") or u.get("company_name") or "—"),
        }
        for u in users
    ]