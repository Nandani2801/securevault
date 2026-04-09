from app import create_app, db
from app.models.user import User
from app.models.vault import VaultEntry
from app.models.audit import AuditLog
import click


app = create_app()


@app.shell_context_processor
def make_shell_context():
    return {"db": db, "User": User, "VaultEntry": VaultEntry, "AuditLog": AuditLog}


@app.cli.command("seed-db")
def seed_db():
    """Seed database with demo users and vault entries."""
    db.create_all()

    if User.query.filter_by(username="admin").first():
        click.echo("Already seeded.")
        return

    # A07: All passwords are weak — no enforcement
    admin = User(username="admin", email="admin@securevault.local", role="admin")
    admin.set_password("admin123")
    db.session.add(admin)

    alice = User(username="alice", email="alice@example.com", role="user")
    alice.set_password("password")
    db.session.add(alice)

    bob = User(username="bob", email="bob@example.com", role="user")
    bob.set_password("123")  # A07: Extremely weak
    db.session.add(bob)

    db.session.flush()

    # Vault entries for alice — A04: stored as base64
    import base64
    def enc(p): return base64.b64encode(p.encode()).decode()

    db.session.add(VaultEntry(user_id=alice.id, site_name="Gmail",   site_url="https://gmail.com",   username="alice@gmail.com", password=enc("alicesecret123"), notes="Personal Gmail"))
    db.session.add(VaultEntry(user_id=alice.id, site_name="GitHub",  site_url="https://github.com",  username="alice_dev",        password=enc("githubPass456"),  notes="Work account"))
    db.session.add(VaultEntry(user_id=alice.id, site_name="Netflix", site_url="https://netflix.com", username="alice@gmail.com", password=enc("netflix@2024")))
    db.session.add(VaultEntry(user_id=bob.id,   site_name="Twitter", site_url="https://twitter.com", username="bob_tweets",       password=enc("twitter123")))

    db.session.commit()
    click.echo("Seeded successfully!")
    click.echo("  admin  / admin123  (admin)")
    click.echo("  alice  / password  (user) — 3 vault entries")
    click.echo("  bob    / 123       (user) — 1 vault entry")


if __name__ == "__main__":
    app.run(debug=True)
