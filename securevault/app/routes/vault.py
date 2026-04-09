from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.vault import VaultEntry
from app.utils.logger import log_event
from app.utils.crypto import encrypt_password, decrypt_password
from datetime import datetime

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")


@vault_bp.route("/")
@login_required
def index():
    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    for entry in entries:
        entry.plain_password = decrypt_password(entry.password)
    return render_template("vault/index.html", entries=entries)


@vault_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        site_name = request.form.get("site_name", "")
        site_url = request.form.get("site_url", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        notes = request.form.get("notes", "")

        entry = VaultEntry(
            user_id=current_user.id,
            site_name=site_name,
            site_url=site_url,
            username=username,
            password=encrypt_password(password),  # A04: base64 only
            notes=notes
        )
        db.session.add(entry)
        db.session.commit()

        log_event("vault_add", user_id=current_user.id,
                  details=f"Added entry for {site_name}",
                  ip_address=request.remote_addr)

        flash("Entry added successfully!", "success")
        return redirect(url_for("vault.index"))

    return render_template("vault/add.html")


@vault_bp.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit(entry_id):
    # A01: No ownership check — any logged-in user can edit any entry by ID
    entry = VaultEntry.query.get_or_404(entry_id)

    if request.method == "POST":
        entry.site_name = request.form.get("site_name", entry.site_name)
        entry.site_url = request.form.get("site_url", entry.site_url)
        entry.username = request.form.get("username", entry.username)
        new_password = request.form.get("password", "")
        if new_password:
            entry.password = encrypt_password(new_password)
        entry.notes = request.form.get("notes", entry.notes)
        entry.updated_at = datetime.utcnow()
        db.session.commit()

        flash("Entry updated!", "success")
        return redirect(url_for("vault.index"))

    entry.plain_password = decrypt_password(entry.password)
    return render_template("vault/edit.html", entry=entry)


@vault_bp.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id):
    # A01: No ownership check — any logged-in user can delete any entry
    entry = VaultEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()

    flash("Entry deleted.", "info")
    return redirect(url_for("vault.index"))


@vault_bp.route("/reveal/<int:entry_id>")
@login_required
def reveal(entry_id):
    # A01: No ownership check — any user can reveal any password
    entry = VaultEntry.query.get_or_404(entry_id)
    return jsonify({"password": decrypt_password(entry.password)})
