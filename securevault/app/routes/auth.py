from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.utils.logger import log_event
from datetime import datetime
from sqlalchemy import text

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # A05: SQL Injection via raw f-string query
        # Input: admin'-- bypasses password check entirely
        try:
            result = db.session.execute(
                text(f"SELECT * FROM users WHERE username = '{username}'")
            ).fetchone()
        except Exception as e:
            flash(f"Database error: {str(e)}", "danger")
            return render_template("auth/login.html")

        if result is None:
            # A09: Failed login not logged
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html")

        user_obj = User.query.filter_by(username=username).first()

        if user_obj is None or not user_obj.check_password(password):
            # A07: No failed attempt counter, no lockout
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html")

        if not user_obj.is_active:
            flash("Your account has been disabled.", "danger")
            return render_template("auth/login.html")

        login_user(user_obj)
        user_obj.last_login = datetime.utcnow()
        db.session.commit()

        log_event("login", user_id=user_obj.id, ip_address=request.remote_addr)

        next_page = request.args.get("next")
        return redirect(next_page or url_for("vault.index"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # A07: No password strength check — "1" is a valid password
        # A07: No email format validation

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html")

        user = User(username=username, email=email)
        user.set_password(password)  # A04: stored as MD5
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
