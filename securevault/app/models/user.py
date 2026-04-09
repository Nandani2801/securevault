from flask_login import UserMixin
from app import db
from datetime import datetime
import hashlib  # A04: MD5 instead of bcrypt


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    is_active = db.Column(db.Boolean, default=True)
    failed_login_count = db.Column(db.Integer, default=0)
    profile_picture = db.Column(db.String(255), default="default.png")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    vault_entries = db.relationship("VaultEntry", backref="owner", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        # A04: MD5 — no salt, cryptographically broken for passwords
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()

    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username}>"
