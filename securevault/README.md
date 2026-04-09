# SecureVault — Vulnerable Flask Password Manager

A deliberately vulnerable web application for security testing demonstrations.
Built with Flask + PostgreSQL (running via Docker).

---

## ⚠️ WARNING
This app is **intentionally insecure**. Do NOT deploy it in any real environment.
It exists purely for security testing and demonstration purposes.

---

## Vulnerabilities Present

| OWASP | Location | Description |
|---|---|---|
| A01 | `/vault/edit/<id>`, `/vault/delete/<id>`, `/admin/*` | No ownership or role checks |
| A02 | `config.py`, `.env` | Hardcoded secret key, debug on, CSRF disabled |
| A03 | `/profile/upload` | Unrestricted file upload, path traversal via filename |
| A04 | `models/user.py`, `utils/crypto.py` | MD5 password hashing, base64 vault storage |
| A05 | `routes/auth.py` login | Raw f-string SQL query — injectable |
| A06 | Entire app | No rate limiting, no lockout, no password policy by design |
| A07 | `routes/auth.py`, `routes/profile.py` | No password strength, no brute force protection |
| A09 | `utils/logger.py` | Logging disabled — no events recorded |
| A10 | `routes/fetcher.py` | SSRF — server fetches any URL without validation |

---

## Prerequisites

- Python 3.9+
- Docker Desktop (running)

---

## Setup & Run

### Step 1 — Start PostgreSQL via Docker

Open PowerShell and run:

```powershell
docker run --name securevault_db `
  -e POSTGRES_DB=securevault `
  -e POSTGRES_USER=securevault `
  -e POSTGRES_PASSWORD=securevault `
  -p 5432:5432 `
  -d postgres:14
```

Wait 5 seconds, then verify it's running:

```powershell
docker ps
```

You should see `securevault_db` with status `Up`.

Verify the database is accessible:

```powershell
docker exec -it securevault_db psql -U securevault -d securevault -c "SELECT 1"
```

You should see `1 row` returned.

---

### Step 2 — Set up Python virtual environment

Navigate into the project folder:

```powershell
cd securevault
```

Create and activate virtual environment:

```powershell
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

---

### Step 3 — Set environment variables

Run these in every new PowerShell session before using Flask:

```powershell
$env:FLASK_APP = "run.py"
$env:DATABASE_URL = "postgresql://securevault:securevault@localhost:5432/securevault"
```

---

### Step 4 — Initialise the database

```powershell
flask db init
flask db migrate -m "initial"
flask db upgrade
flask seed-db
```

Expected output from `flask seed-db`:
```
Database seeded successfully!
Users created:
  admin / admin123  (role: admin)
  alice / password  (role: user)
  bob   / 123       (role: user)
```

---

### Step 5 — Run the app

```powershell
flask run
```

Visit **http://localhost:5000** in your browser.

---

## Every Time You Restart

Docker container may stop when you restart your PC. Run this to bring it back:

```powershell
docker start securevault_db
```

Then in your project folder:

```powershell
venv\Scripts\activate
$env:FLASK_APP = "run.py"
$env:DATABASE_URL = "postgresql://securevault:securevault@localhost:5432/securevault"
flask run
```

---

## Demo Accounts

| Username | Password | Role |
|---|---|---|
| admin | admin123 | Admin |
| alice | password | User — 3 vault entries (Gmail, GitHub, Netflix) |
| bob | 123 | User — 1 vault entry (Twitter) |

---

## Vulnerability Demos

### A05 — SQL Injection
On the login page enter username: `admin'--` with **any** password.
Authentication is bypassed entirely — you get logged in as admin without knowing the password.

### A01 — Broken Access Control
1. Log in as `bob` (password: `123`)
2. Go to `http://localhost:5000/vault/edit/1` in the URL bar
3. You can now edit Alice's Gmail vault entry — even though it belongs to Alice
4. Visit `http://localhost:5000/admin/dashboard` — you get full admin access as a regular user

### A10 — SSRF
1. Log in and go to **Site Fetcher** in the navbar
2. Enter `http://127.0.0.1:5432` — probes the internal PostgreSQL port
3. Enter `http://169.254.169.254/latest/meta-data/` — AWS cloud metadata endpoint
4. The server makes the request on your behalf and returns the response

### A04 — Weak Cryptography
Register a new user with password `hello`.
Check the database directly:
```powershell
docker exec -it securevault_db psql -U securevault -d securevault -c "SELECT username, password_hash FROM users;"
```
You'll see MD5 hashes — no salt, easily crackable.

For vault entries:
```powershell
docker exec -it securevault_db psql -U securevault -d securevault -c "SELECT site_name, password FROM vault_entries;"
```
Passwords are stored as base64. Decode one:
```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxpY2VzZWNyZXQxMjM="))
```

### A03 — Unsafe File Upload
1. Log in and go to **Profile**
2. Upload a file named `test.html` or `evil.php`
3. It gets saved to `app/static/uploads/` with its original name — no validation

### A07 — Authentication Failures
Register a new account with password `1` — it is accepted with no complaint.
There is also no account lockout — you can attempt login thousands of times with no block.

### A09 — No Logging
Go to **Admin → Audit Logs**.
Despite all the activity (logins, vault accesses, failed attempts), the log is completely empty.
All security events are silently swallowed.

---

## Checking the Database Directly

Connect to the database anytime:

```powershell
docker exec -it securevault_db psql -U securevault -d securevault
```

Useful queries inside psql:

```sql
-- See all users and their hashed passwords
SELECT id, username, email, role, password_hash FROM users;

-- See all vault entries (base64 encoded passwords)
SELECT id, user_id, site_name, username, password FROM vault_entries;

-- See audit logs (will be empty — A09)
SELECT * FROM audit_logs;

-- Exit
\q
```

---

## Stopping Everything

Stop the Flask app: `Ctrl+C` in the terminal

Stop the Docker container:
```powershell
docker stop securevault_db
```

Start it again next time:
```powershell
docker start securevault_db
```

---

## File Structure

```
securevault/
├── app/
│   ├── __init__.py          Flask app factory
│   ├── config.py            Vulnerable config (hardcoded key, debug on)
│   ├── models/
│   │   ├── user.py          User model — MD5 password hashing (A04)
│   │   ├── vault.py         VaultEntry model — base64 password storage (A04)
│   │   └── audit.py         AuditLog model — never written to (A09)
│   ├── routes/
│   │   ├── auth.py          Login with SQL injection (A05), no lockout (A07)
│   │   ├── vault.py         CRUD with no ownership checks (A01)
│   │   ├── admin.py         Admin panel with no role checks (A01)
│   │   ├── profile.py       Unsafe file upload (A03)
│   │   └── fetcher.py       SSRF endpoint (A10)
│   ├── templates/           Jinja2 HTML templates
│   ├── static/
│   │   ├── css/style.css
│   │   ├── js/vault.js
│   │   └── uploads/         File upload destination (web accessible)
│   └── utils/
│       ├── crypto.py        base64 encoding as "encryption" (A04)
│       ├── validators.py    No-op validators — everything passes (A03, A10)
│       └── logger.py        Logging permanently disabled (A09)
├── migrations/              Flask-Migrate / Alembic files
├── run.py                   Entry point + flask seed-db command
├── requirements.txt
└── .env                     Hardcoded credentials committed to repo (A02)
```

---

## Troubleshooting

**`flask` command not found**
Make sure your venv is activated — prompt should show `(venv)`.

**Password authentication failed**
Your Docker container stopped. Run `docker start securevault_db` then retry.

**`flask db init` says already exists**
```powershell
Remove-Item -Recurse -Force migrations
flask db init
flask db migrate -m "initial"
flask db upgrade
```

**Database already seeded message**
That's fine — it means `flask seed-db` ran before. Your data is already there.

**Textual SQL expression error on login**
Make sure `app/routes/auth.py` wraps the raw SQL with `text()`:
```python
from sqlalchemy import text
result = db.session.execute(
    text(f"SELECT * FROM users WHERE username = '{username}'")
).fetchone()
```
