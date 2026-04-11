import pytest
from app import create_app, db as _db
from app.models.user import User
from app.models.vault import VaultEntry


# -------------------------
# App Fixture
# -------------------------
@pytest.fixture(scope="session")
def app():
    """Create a Flask app configured for testing using in-memory SQLite."""
    test_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key",
        "LOGGING_ENABLED": False,
    })
    return test_app


# -------------------------
# Database Fixture
# -------------------------
@pytest.fixture(scope="function")
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


# -------------------------
# Client Fixture
# -------------------------
@pytest.fixture(scope="function")
def client(app, db):
    """Flask test client with fresh seeded data per test."""
    with app.app_context():
        # Create users
        admin = User(username="admin", email="admin@test.com", role="admin")
        admin.set_password("admin123")

        alice = User(username="alice", email="alice@test.com", role="user")
        alice.set_password("password")

        bob = User(username="bob", email="bob@test.com", role="user")
        bob.set_password("123")

        db.session.add_all([admin, alice, bob])
        db.session.commit()

        # Create vault entries
        entry1 = VaultEntry(
            user_id=alice.id,
            site_name="Gmail",
            site_url="https://gmail.com",
            username="alice@gmail.com",
            password="YWxpY2VzZWNyZXQxMjM=",
            notes="Personal email"
        )

        entry2 = VaultEntry(
            user_id=alice.id,
            site_name="GitHub",
            site_url="https://github.com",
            username="alice_dev",
            password="Z2l0aHViUGFzczQ1Ng==",
        )

        bob_entry = VaultEntry(
            user_id=bob.id,
            site_name="Twitter",
            site_url="https://twitter.com",
            username="bob_tweets",
            password="dHdpdHRlcjEyMw==",
        )

        db.session.add_all([entry1, entry2, bob_entry])
        db.session.commit()

    with app.test_client() as test_client:
        yield test_client


# -------------------------
# Login Fixtures
# -------------------------
@pytest.fixture(scope="function")
def logged_in_alice(client):
    client.post("/login", data={
        "username": "alice",
        "password": "password"
    }, follow_redirects=True)
    return client


@pytest.fixture(scope="function")
def logged_in_bob(client):
    client.post("/login", data={
        "username": "bob",
        "password": "123"
    }, follow_redirects=True)
    return client


@pytest.fixture(scope="function")
def logged_in_admin(client):
    client.post("/login", data={
        "username": "admin",
        "password": "admin123"
    }, follow_redirects=True)
    return client