# auth_utils.py
from functools import wraps
from flask import session, redirect, url_for, abort, g

def normalize_role(value, default="limited"):
    return (value if value is not None else default).strip().lower()

def login_required():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                return redirect(url_for("login"))
            g.admin_role = normalize_role(session.get("admin_role"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

def roles_required(*allowed_roles):
    normalized_allowed = { normalize_role(r, "") for r in allowed_roles }
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                return redirect(url_for("login"))
            role = normalize_role(session.get("admin_role"))
            if role not in normalized_allowed:
                abort(403)
            g.admin_role = role
            return f(*args, **kwargs)
        return wrapper
    return decorator

def require_roles(*roles):
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    role = normalize_role(session.get("admin_role", ""))
    allowed = { normalize_role(r, "") for r in roles }
    if role not in allowed:
        abort(403)
    return None
