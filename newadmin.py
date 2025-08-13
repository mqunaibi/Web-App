# newadmin.py
from flask import (
    Blueprint, render_template, session, redirect, url_for,
    request, jsonify, flash, abort, g
)
from functools import wraps
from urllib.parse import unquote

# دوال الـ DAL
from api_handler import (
    get_pending_users, get_approved_users, get_rejected_users,
    approve_user, reject_user, delete_user, add_admin_user
)

# log_admin_action قد لا تكون موجودة في بعض الإصدارات؛ سنحاول استيرادها إن وجدت
try:
    from api_handler import log_admin_action as _log_admin_action
except Exception:  # pragma: no cover
    _log_admin_action = None

newadmin_bp = Blueprint("newadmin", __name__, url_prefix="")

# ------------------------------
# Helpers: role-based authorization + context
# ------------------------------

def _normalize_role(value: str, default: str = "limited") -> str:
    """Trim + lowercase for consistent comparisons."""
    return (value if value is not None else default).strip().lower()


def roles_required(*allowed_roles):
    """
    Decorator to protect routes by role.
    - Requires user to be logged in.
    - Allows only roles listed in `allowed_roles` (normalized).
    """
    normalized_allowed = {_normalize_role(r, "") for r in allowed_roles}

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
    """Enforce login for all blueprint routes. Also prime g.admin_role (normalized) for templates."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    g.admin_role = _normalize_role(session.get("admin_role"))


@newadmin_bp.app_context_processor
def inject_role():
    """Inject the current admin role into all templates as `admin_role` (normalized)."""
    return {"admin_role": _normalize_role(session.get("admin_role"))}


def _company_filter_from_session():
    """
    يعيد اسم الشركة المستخدم لتقييد الرؤية إن وُجد.
    - super أو company == 'All' => None (عرض الكل)
    - غير ذلك => اسم الشركة من الجلسة
    """
    role = _normalize_role(session.get("admin_role"))
    company = (session.get("admin_company") or "").strip()
    if role == "super" or company.lower() == "all" or not company:
        return None
    return company


def _normalize_user(u: dict) -> dict:
    """تطبيع مفاتيح المستخدمين لتوافق واجهة DataTables."""
    return {
        "email": u.get("email"),
        "phone": u.get("phone"),
        "company": u.get("company") or u.get("company_name") or "",
        "device_name": u.get("device_name"),
        "device_uuid": u.get("device_uuid"),
        "created_at": u.get("created_at"),
    }


def _fetch_with_optional_company(fn, company_filter):
    """
    يستدعي دالة DAL مع باراميتر الشركة إن كانت تدعمه،
    وإلا يستدعيها بدون باراميتر (توافقًا مع إصدارات أقدم).
    """
    try:
        return fn(company_filter)
    except TypeError:
        # نسخة قديمة لا تقبل باراميتر
        return fn()


def _ensure_can_edit():
    role = _normalize_role(session.get("admin_role"))
    if role not in ("super", "limited"):
        abort(403)


def _log(action: str, details: str = ""):
    if _log_admin_action:
        try:
            _log_admin_action(
                admin_username=session.get("admin_user") or "unknown",
                action=action,
                details=details,
                ip_address=request.remote_addr,
            )
        except Exception:
            # لا نعطل الطلب بسبب فشل السجل
            pass


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
    # الصفحة نفسها لا تحتاج عدّادات من السيرفر (الواجهة تجلبها AJAX)
    return render_template("newadmin.html")


# ------------------------------
# Users data (JSON) — super + limited + viewer
# ------------------------------
@newadmin_bp.route("/newadmin_data")
@roles_required("super", "limited", "viewer")
def admin_data():
    filt = _company_filter_from_session()
    pending_raw = _fetch_with_optional_company(get_pending_users, filt) or []
    approved_raw = _fetch_with_optional_company(get_approved_users, filt) or []
    rejected_raw = _fetch_with_optional_company(get_rejected_users, filt) or []

    return jsonify(
        {
            "pending_users": [_normalize_user(u) for u in pending_raw],
            "approved_users": [_normalize_user(u) for u in approved_raw],
            "rejected_users": [_normalize_user(u) for u in rejected_raw],
        }
    )


# ------------------------------
# Sensitive actions — super + limited (viewer ممنوع)
# ------------------------------
@newadmin_bp.route("/newapprove/<path:email>", methods=["POST"])
@roles_required("super", "limited")
def newapprove(email):
    _ensure_can_edit()
    email = unquote(email)
    res = approve_user(email)
    ok = res is True
    if ok:
        _log("approve_user", f"email={email}")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": str(res)}), 400


@newadmin_bp.route("/newreject/<path:email>", methods=["POST"])
@roles_required("super", "limited")
def newreject(email):
    _ensure_can_edit()
    email = unquote(email)
    res = reject_user(email)
    ok = res is True
    if ok:
        _log("reject_user", f"email={email}")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": str(res)}), 400


@newadmin_bp.route("/newdelete_user/<path:email>", methods=["POST", "DELETE"])
@roles_required("super", "limited")
def newdelete_user(email):
    _ensure_can_edit()
    email = unquote(email)
    res = delete_user(email)
    ok = res is True
    if ok:
        _log("delete_user", f"email={email}")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": str(res)}), 400


# ------------------------------
# Admin add (manage admins) — super only (اختياري)
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

        if not username:
            flash("Username is required.", "danger")
            return render_template("admin_add.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("admin_add.html")

        result = add_admin_user(username, password, role, is_active, email, company_name)
        if result is True:
            flash("Admin added successfully!", "success")
            return redirect(url_for("admin_manage"))
        else:
            flash(str(result), "danger")
    return render_template("admin_add.html")

