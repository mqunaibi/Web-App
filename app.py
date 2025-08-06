from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import logging
logging.basicConfig(level=logging.WARNING)
from dotenv import load_dotenv
from newadmin import newadmin_bp
import os
from api_handler import execute_query

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
            session["logged_in"] = True
            session["admin_user"] = username
            session["admin_role"] = result[0]["role"]
            return redirect("/newadmin")
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("index.html")
@app.after_request
def add_cache_control(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

if __name__ == "__main__":
    app.run(debug=True)
