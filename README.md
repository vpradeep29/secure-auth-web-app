# SecureAuth — Secure Web Authentication

SecureAuth is a Flask web application project demonstrating secure authentication and access-control patterns. This repository version is reconstructed from prior project notes; the original development machine and exact original source files were unavailable, so this is not an exact recovery.

## Implemented in this version

- Registration and login with Flask-Login
- Argon2 password hashing
- CSRF protection for Flask-WTF forms and state-changing POST routes
- Authenticated dashboard and role-based administrator route
- Database-backed audit events for registration, login success/failure, logout, and administrator account-status changes
- Database-backed administrator counts, user list, and recent event list
- Admin ability to activate/deactivate other accounts, protected by CSRF
- HTTPOnly and SameSite=Lax session cookies, configurable Secure cookie flag
- Baseline security response headers
- Responsive dark dashboard with Overview, Security, Activity, and Settings sections

## Setup (Windows PowerShell)

Python 3.11 or later is recommended.

```powershell
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the generated secret into .env as SECRET_KEY. Do not commit .env.

Initialize the database and create an administrator:

```powershell
flask --app run.py init-db
flask --app run.py create-admin
python run.py
```

Open http://127.0.0.1:5000.

## Main routes

| Route | Method | Access |
|---|---|---|
| / | GET | Public |
| /register | GET, POST | Public |
| /login | GET, POST | Public |
| /dashboard | GET | Authenticated |
| /admin | GET | Administrator |
| /admin/users/<id>/status | POST | Administrator |
| /logout | POST | Authenticated |

## Security limitations

This is an educational project, not a production-ready security certification. Rate limiting, account lockout, password reset, email verification, user password-change workflow, and comprehensive automated tests are not yet implemented. The built-in Flask development server must not be used in production. Use HTTPS, a production WSGI server, a strong deployment secret, appropriate backups, and reviewed proxy/logging configuration before public deployment.

The database initializer uses db.create_all() for a fresh local database. Existing databases should be backed up before changing model schemas; formal Alembic migration history is not currently included in this reconstructed repository.

## Validation status

The code has not yet been executed in a clean environment as part of this commit. Run the test suite before relying on the application or claiming verified functionality.
