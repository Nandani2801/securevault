from app import db
from app.models.audit import AuditLog
from flask import current_app


def log_event(action, user_id=None, details=None, ip_address=None, status="success"):
    # A09: Logging disabled — no events are ever recorded
    if not current_app.config.get("LOGGING_ENABLED", False):
        return
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            status=status
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass
