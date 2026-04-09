"""
Unit tests for Vault — routes/vault.py
"""

import pytest
from app.models.vault import VaultEntry
from app.models.user import User


class TestVaultIndex:

    def test_vault_requires_login(self, client):
        response = client.get("/vault/", follow_redirects=True)
        assert b"login" in response.data.lower()

    def test_vault_shows_own_entries(self, logged_in_alice):
        response = logged_in_alice.get("/vault/")
        assert response.status_code == 200
        assert b"Gmail" in response.data
        assert b"GitHub" in response.data

    def test_vault_does_not_show_other_users_entries(self, logged_in_alice):
        response = logged_in_alice.get("/vault/")
        assert b"Twitter" not in response.data


class TestVaultAdd:

    def test_add_entry_get(self, logged_in_alice):
        response = logged_in_alice.get("/vault/add")
        assert response.status_code == 200

    def test_add_entry_success(self, logged_in_alice, app, db):
        response = logged_in_alice.post("/vault/add", data={
            "site_name": "TestSite",
            "site_url": "https://testsite.com",
            "username": "testuser",
            "password": "testpass123",
            "notes": "some notes"
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b"Entry added successfully" in response.data

        # DB check needs context
        with app.app_context():
            entry = VaultEntry.query.filter_by(site_name="TestSite").first()
            assert entry is not None

    def test_add_entry_stores_base64_not_plaintext(self, logged_in_alice, app, db):
        logged_in_alice.post("/vault/add", data={
            "site_name": "Base64Test",
            "site_url": "",
            "username": "user",
            "password": "myrealpassword",
            "notes": ""
        }, follow_redirects=True)

        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(
                user_id=alice.id,
                site_name="Base64Test"
            ).first()

        assert entry is not None
        assert entry.password != "myrealpassword"

        import base64
        decoded = base64.b64decode(entry.password.encode()).decode()
        assert decoded == "myrealpassword"


class TestVaultEdit:

    def test_edit_own_entry(self, logged_in_alice, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_alice.post(f"/vault/edit/{entry.id}", data={
            "site_name": "Gmail Updated",
            "site_url": "https://gmail.com",
            "username": "alice@gmail.com",
            "password": "newpassword",
            "notes": ""
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b"updated" in response.data.lower()

    def test_bob_can_edit_alices_entry(self, logged_in_bob, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_bob.post(f"/vault/edit/{entry.id}", data={
            "site_name": "Hacked by Bob",
            "username": "hacker",
            "password": "hacked",
        }, follow_redirects=True)

        assert response.status_code == 200  # intentional vulnerability


    def test_bob_can_view_edit_form_for_alices_entry(self, logged_in_bob, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_bob.get(f"/vault/edit/{entry.id}")
        assert response.status_code == 200  # intentional


class TestVaultDelete:

    def test_delete_own_entry(self, logged_in_alice, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_alice.post(
            f"/vault/delete/{entry.id}",
            follow_redirects=True
        )

        assert response.status_code == 200
        assert b"deleted" in response.data.lower()

    def test_bob_can_delete_alices_entry(self, logged_in_bob, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_bob.post(
            f"/vault/delete/{entry.id}",
            follow_redirects=True
        )

        assert response.status_code == 200  # intentional vulnerability


class TestVaultReveal:

    def test_reveal_own_password(self, logged_in_alice, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_alice.get(f"/vault/reveal/{entry.id}")
        assert response.status_code == 200
        assert "password" in response.get_json()

    def test_bob_can_reveal_alices_password(self, logged_in_bob, app):
        with app.app_context():
            alice = User.query.filter_by(username="alice").first()
            entry = VaultEntry.query.filter_by(user_id=alice.id).first()

        response = logged_in_bob.get(f"/vault/reveal/{entry.id}")
        assert response.status_code == 200  # intentional vulnerability

    def test_reveal_requires_login(self, client, app):
        with app.app_context():
            entry = VaultEntry.query.first()

        response = client.get(f"/vault/reveal/{entry.id}", follow_redirects=True)
        assert b"login" in response.data.lower()
