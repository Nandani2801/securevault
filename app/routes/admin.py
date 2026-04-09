from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.audit import AuditLog

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# A01: No server-side role check on ANY of these routes
# The nav link is hidden in the UI but routes are fully open to any logged-in user

@admin_bp.route("/dashboard")
@login_required
def dashboard():
    # Missing: if not current_user.is_admin(): abort(403)
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_logs = AuditLog.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template("admin/dashboard.html",
                           total_users=total_users,
                           active_users=active_users,
                           total_logs=total_logs,
                           recent_logs=recent_logs)


@admin_bp.route("/users")
@login_required
def users():
    # A01: Any user can see all registered accounts
    all_users = User.query.all()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/toggle/<int:user_id>", methods=["POST"])
@login_required
def toggle_user(user_id):
    # A01: Any user can disable/enable any account
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    status = "enabled" if user.is_active else "disabled"
    flash(f"User {user.username} has been {status}.", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/logs")
@login_required
def logs():
    # A01: Any user can read all audit logs
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin/logs.html", logs=all_logs)
