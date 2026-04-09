from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_required, current_user
from app import db
from app.utils.validators import allowed_file, sanitize_filename
from app.utils.logger import log_event
import os

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")


@profile_bp.route("/")
@login_required
def index():
    return render_template("profile/index.html")


@profile_bp.route("/update", methods=["POST"])
@login_required
def update():
    new_email = request.form.get("email", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_email:
        # A05: No email format validation
        current_user.email = new_email

    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("profile.index"))
        # A07: No password strength check on update
        current_user.set_password(new_password)

    db.session.commit()
    log_event("profile_update", user_id=current_user.id, ip_address=request.remote_addr)
    flash("Profile updated!", "success")
    return redirect(url_for("profile.index"))


@profile_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    if "profile_picture" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("profile.index"))

    file = request.files["profile_picture"]

    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("profile.index"))

    if allowed_file(file.filename):
        # A03: Original filename used — path traversal possible
        # e.g. filename = "../../config.py" overwrites app config
        filename = sanitize_filename(file.filename)
        upload_path = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_path, exist_ok=True)

        # A03: Dangerous file types (.php, .html, .js) saved to web-accessible folder
        file.save(os.path.join(upload_path, filename))
        current_user.profile_picture = filename
        db.session.commit()
        flash("Profile picture updated!", "success")

    return redirect(url_for("profile.index"))
