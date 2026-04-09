"""
Unit tests for Cryptographic utilities — utils/crypto.py
"""

import pytest
import hashlib
import base64
from app.utils.crypto import encrypt_password, decrypt_password
from app.models.user import User


# -------------------------
# Vault Encryption Tests
# -------------------------
class TestVaultPasswordEncryption:

    def test_encrypt_returns_base64(self):
        result = encrypt_password("mypassword")

        try:
            decoded = base64.b64decode(result.encode()).decode()
            assert decoded == "mypassword"
        except Exception:
            pytest.fail("encrypt_password did not return valid base64")

    def test_decrypt_reverses_encryption(self):
        original = "supersecretpassword"
        encrypted = encrypt_password(original)
        decrypted = decrypt_password(encrypted)
        assert decrypted == original

    def test_encrypt_is_not_real_encryption(self):
        password = "myvaultpassword"
        encoded = encrypt_password(password)

        decoded = base64.b64decode(encoded.encode()).decode()
        assert decoded == password  # intentional vulnerability

    def test_different_passwords_produce_different_encodings(self):
        enc1 = encrypt_password("password1")
        enc2 = encrypt_password("password2")
        assert enc1 != enc2

    def test_decrypt_handles_invalid_input(self):
        result = decrypt_password("not-valid-base64!!!")
        assert result == "not-valid-base64!!!"

    def test_empty_password_encrypt_decrypt(self):
        encrypted = encrypt_password("")
        decrypted = decrypt_password(encrypted)
        assert decrypted == ""


# -------------------------
# User Password Hashing Tests
# -------------------------
class TestUserPasswordHashing:

    def test_set_password_uses_md5(self, app):
        with app.app_context():
            user = User(username="testcrypto", email="testcrypto@test.com")
            user.set_password("mypassword")

            expected_md5 = hashlib.md5("mypassword".encode()).hexdigest()
            assert user.password_hash == expected_md5

    def test_md5_has_no_salt(self, app):
        with app.app_context():
            user1 = User(username="user_salt1", email="salt1@test.com")
            user1.set_password("samepassword")

            user2 = User(username="user_salt2", email="salt2@test.com")
            user2.set_password("samepassword")

        assert user1.password_hash == user2.password_hash  # intentional vulnerability

    def test_check_password_correct(self, app):
        with app.app_context():
            user = User(username="checkpw", email="checkpw@test.com")
            user.set_password("correctpassword")

            assert user.check_password("correctpassword") is True

    def test_check_password_wrong(self, app):
        with app.app_context():
            user = User(username="checkpw2", email="checkpw2@test.com")
            user.set_password("correctpassword")

            assert user.check_password("wrongpassword") is False

    def test_md5_is_crackable(self):
        known_md5 = hashlib.md5("password".encode()).hexdigest()
        assert known_md5 == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_password_not_stored_as_plaintext(self, app):
        with app.app_context():
            user = User(username="notplain", email="notplain@test.com")
            user.set_password("mypassword")

            assert user.password_hash != "mypassword"