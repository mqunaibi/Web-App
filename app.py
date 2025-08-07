from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import logging
logging.basicConfig(level=logging.WARNING)
from dotenv import load_dotenv
from newadmin import newadmin_bp
import os
from api_handler import execute_query
from api_handler import get_admin_by_id, update_admin_user
from api_handler import toggle_admin_status
from api_handler import get_all_admins

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "mysecret")

app.register_blueprint(newadmin_bp)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        result = execute_query(
            "SELECT * FROM admin_users WHERE username = %s AND password = %s",
            (username, password),
            fetch=True
        )

        if result and len(result) > 0:
            session["admin_logged_in"] = True
            session["admin_user"] = username
            session["admin_role"] = result[0]["role"]
            return redirect("/admin-dashboard")
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("index.html")
@app.after_request
def add_cache_control(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response


@app.route('/admin-edit/<int:admin_id>', methods=['GET', 'POST'])
def admin_edit(admin_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))

    admin = get_admin_by_id(admin_id)
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for('admin_manage'))

    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        is_active = 1 if request.form.get('is_active') == 'on' else 0

        result = update_admin_user(admin_id, username, role, is_active)
        if result is True:
            flash("Admin updated successfully!", "success")
            return redirect(url_for('admin_manage'))
        else:
            flash(f"Error: {result}", "danger")

    return render_template('admin_edit.html', admin=admin)

def get_admin_by_id(admin_id):
    result = execute_query(
        "SELECT id, username, role, is_active FROM admin_users WHERE id = %s",
        (admin_id,),
        fetch=True
    )
    return result[0] if result else None

def update_admin_user(admin_id, username, role, is_active):
    return execute_query(
        "UPDATE admin_users SET username = %s, role = %s, is_active = %s WHERE id = %s",
        (username, role, is_active, admin_id)
    )

from api_handler import delete_admin_user

@app.route('/admin-delete/<int:admin_id>', methods=['GET'])
def admin_delete(admin_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))

    result = delete_admin_user(admin_id)
    if result is True:
        flash("Admin deleted successfully!", "success")
    else:
        flash(f"Error deleting admin: {result}", "danger")
    return redirect(url_for('admin_manage'))

@app.route('/admin-toggle/<int:admin_id>', methods=['GET'])
def admin_toggle(admin_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))

    result = toggle_admin_status(admin_id)
    if result is True:
        flash("Admin status updated.", "success")
    else:
        flash(f"Error updating status: {result}", "danger")
    return redirect(url_for('admin_manage'))

@app.route("/admin-manage")
def admin_manage():
    if 'admin_logged_in' not in session:
        return redirect(url_for("login"))
    
    admins = get_all_admins()
    return render_template("admin_manage.html", admins=admins)


if __name__ == "__main__":
    app.run(debug=True)