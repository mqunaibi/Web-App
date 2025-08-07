from api_handler import add_admin_user 
from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, flash
from api_handler import (
    get_pending_users, get_approved_users, get_rejected_users,
    approve_user, reject_user, delete_user
)

newadmin_bp = Blueprint("newadmin", __name__)

#  Blueprint
@newadmin_bp.before_request
def require_login():
    # 
    if request.path == "/login":
        return
    if not session.get("logged_in"):
        return redirect("/login")

# 
@newadmin_bp.route("/newadmin")
def newadmin_page():
    pending_users = get_pending_users() or []
    approved_users = get_approved_users() or []
    rejected_users = get_rejected_users() or []

    return render_template("newadmin.html",
                           pending_count=len(pending_users),
                           approved_count=len(approved_users),
                           rejected_count=len(rejected_users))

# (pending + approved + rejected)
@newadmin_bp.route("/newadmin_data")
def admin_data():
    return jsonify({
        "pending_users": format_users(get_pending_users() or []),
        "approved_users": format_users(get_approved_users() or []),
        "rejected_users": format_users(get_rejected_users() or [])
    })

# 
@newadmin_bp.route("/newapprove/<email>", methods=["POST"])
def newapprove(email):
    result = approve_user(email)
    return jsonify({"success": result is True, "message": str(result)})

# 
@newadmin_bp.route("/newreject/<email>", methods=["POST"])
def newreject(email):
    result = reject_user(email)
    return jsonify({"success": result is True, "message": str(result)})

# 
@newadmin_bp.route("/newdelete_user/<email>")
def newdelete_user(email):
    result = delete_user(email)
    return jsonify({"success": result is True, "message": str(result)})

# 
@newadmin_bp.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect("/login")

def format_users(users):
    return [
        {
            "email": user["email"],
            "phone": user["phone"],
            "device_name": user.get("device_name", "N/A"),
            "device_type": user.get("device_type", "N/A"),
            "ip_address": user.get("ip_address", "N/A"),
            "registered_at": user.get("created_at", "N/A"),
            "device_uuid": user.get("device_uuid", "N/A")
        } for user in users
    ]

@newadmin_bp.route("/admin-add", methods=["GET", "POST"])
def admin_add():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        is_active = 1 if 'is_active' in request.form else 0

        result = add_admin_user(username, password, role, is_active)
        if result is True:
            flash("Admin added successfully!", "success")
            return redirect(url_for('admin_manage'))
        else:
            flash(result, "danger")

    return render_template('admin_add.html')