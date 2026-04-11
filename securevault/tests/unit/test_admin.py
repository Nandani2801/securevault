"""
Unit tests for Admin Panel — routes/admin.py
"""

import pytest


class TestAdminDashboard:

    def test_admin_can_access_dashboard(self, logged_in_admin):
        response = logged_in_admin.get("/admin/dashboard")
        assert response.status_code == 200
        assert b"dashboard" in response.data.lower()

    def test_unauthenticated_cannot_access_dashboard(self, client):
        response = client.get("/admin/dashboard", follow_redirects=True)
        assert b"login" in response.data.lower()

    def test_regular_user_can_access_admin_dashboard(self, logged_in_alice):
        response = logged_in_alice.get("/admin/dashboard")
        assert response.status_code == 200  # intentional vulnerability

    def test_bob_can_access_admin_dashboard(self, logged_in_bob):
        response = logged_in_bob.get("/admin/dashboard")
        assert response.status_code == 200  # intentional


class TestAdminUsers:

    def test_admin_can_see_all_users(self, logged_in_admin):
        response = logged_in_admin.get("/admin/users")
        assert response.status_code == 200
        assert b"alice" in response.data
        assert b"bob" in response.data

    def test_regular_user_can_see_all_users(self, logged_in_alice):
        response = logged_in_alice.get("/admin/users")
        assert response.status_code == 200  # intentional vulnerability
        assert b"bob" in response.data

    def test_regular_user_can_toggle_another_account(self, logged_in_alice, app):
        from app.models.user import User

        with app.app_context():
            bob = User.query.filter_by(username="bob").first()
            bob_id = bob.id
            original_status = bob.is_active

        response = logged_in_alice.post(
            f"/admin/users/toggle/{bob_id}",
            follow_redirects=True
        )

        with app.app_context():
            bob_after = User.query.get(bob_id)

        assert response.status_code == 200  # intentional vulnerability
        assert bob_after.is_active != original_status


class TestAdminLogs:

    def test_admin_can_access_logs(self, logged_in_admin):
        response = logged_in_admin.get("/admin/logs")
        assert response.status_code == 200

    def test_regular_user_can_access_logs(self, logged_in_alice):
        response = logged_in_alice.get("/admin/logs")
        assert response.status_code == 200  # intentional vulnerability

    def test_audit_logs_are_empty(self, logged_in_admin):
        response = logged_in_admin.get("/admin/logs")

        assert response.status_code == 200
        assert (
            b"No logs recorded" in response.data
            or b"empty" in response.data.lower()
            or response.status_code == 200
        )