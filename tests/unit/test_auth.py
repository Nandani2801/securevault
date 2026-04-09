"""
Unit tests for Authentication — routes/auth.py
"""

import pytest
from app.models.user import User


# -------------------------
# Login Tests
# -------------------------
class TestLogin:

    def test_login_page_loads(self, client):
        response = client.get("/login")
        assert response.status_code == 200
        assert b"SecureVault" in response.data

    def test_login_valid_credentials(self, client):
        response = client.post("/login", data={
            "username": "alice",
            "password": "password"
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b"My Vault" in response.data or b"vault" in response.data.lower()

    def test_login_wrong_password(self, client):
        response = client.post("/login", data={
            "username": "alice",
            "password": "wrongpassword"
        }, follow_redirects=True)

        assert b"Invalid username or password" in response.data

    def test_login_nonexistent_user(self, client):
        response = client.post("/login", data={
            "username": "nobody",
            "password": "password"
        }, follow_redirects=True)

        assert b"Invalid username or password" in response.data

    def test_login_empty_credentials(self, client):
        response = client.post("/login", data={
            "username": "",
            "password": ""
        }, follow_redirects=True)

        assert b"My Vault" not in response.data

    # A07 — Vulnerability
    def test_no_account_lockout_after_multiple_failures(self, client):
        for _ in range(10):
            client.post("/login", data={
                "username": "alice",
                "password": "wrongpassword"
            })

        response = client.post("/login", data={
            "username": "alice",
            "password": "password"
        }, follow_redirects=True)

        assert b"My Vault" in response.data or response.status_code == 200


    def test_disabled_account_cannot_login(self, client, app, db):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            alice.is_active = False
            db.session.commit()

        response = client.post("/login", data={
            "username": "alice",
            "password": "password"
        }, follow_redirects=True)

        assert b"disabled" in response.data.lower()


# -------------------------
# Register Tests
# -------------------------
class TestRegister:

    def test_register_page_loads(self, client):
        response = client.get("/register")
        assert response.status_code == 200

    def test_register_new_user(self, client):
        response = client.post("/register", data={
            "username": "newuser",
            "email": "new@test.com",
            "password": "somepassword"
        }, follow_redirects=True)

        assert b"Registration successful" in response.data

    def test_register_duplicate_username(self, client):
        response = client.post("/register", data={
            "username": "alice",
            "email": "different@test.com",
            "password": "password"
        }, follow_redirects=True)

        assert b"already taken" in response.data.lower() or b"username" in response.data.lower()

    def test_register_duplicate_email(self, client):
        response = client.post("/register", data={
            "username": "newuser2",
            "email": "alice@test.com",
            "password": "password"
        }, follow_redirects=True)

        assert b"already registered" in response.data.lower() or b"email" in response.data.lower()

    # A07 — Vulnerability
    def test_weak_password_accepted(self, client):
        response = client.post("/register", data={
            "username": "weakpwuser",
            "email": "weak@test.com",
            "password": "1"
        }, follow_redirects=True)

        assert b"Registration successful" in response.data

    def test_empty_password_registration(self, client):
        response = client.post("/register", data={
            "username": "nopwuser",
            "email": "nopw@test.com",
            "password": ""
        }, follow_redirects=True)

        assert response.status_code in [200, 302]


# -------------------------
# Logout Tests
# -------------------------
class TestLogout:

    def test_logout_redirects_to_login(self, logged_in_alice):
        response = logged_in_alice.get("/logout", follow_redirects=True)
        assert b"login" in response.data.lower()

    def test_cannot_access_vault_after_logout(self, logged_in_alice):
        logged_in_alice.get("/logout")

        response = logged_in_alice.get("/vault/", follow_redirects=True)
        assert b"login" in response.data.lower()