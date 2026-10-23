from getpass import getpass

import click
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from config import Config

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "main.login"
login_manager.login_message_category = "error"


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    from app.models import AuditLog, User  # noqa: F401
    from app.routes import main

    app.register_blueprint(main)

    @app.cli.command("init-db")
    def init_db():
        """Create database tables for a fresh local installation."""
        with app.app_context():
            db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True, help="Administrator email address")
    def create_admin(email):
        """Create or promote an administrator account using a hidden password prompt."""
        from app.security.passwords import hash_password

        email = email.strip().lower()
        password = getpass("New admin password: ")
        confirmation = getpass("Confirm admin password: ")

        if len(password) < 12:
            raise click.ClickException("Password must contain at least 12 characters.")
        if password != confirmation:
            raise click.ClickException("Passwords do not match.")

        with app.app_context():
            user = User.query.filter_by(email=email).first()
            if user:
                user.role = "admin"
                user.is_active = True
                # Existing accounts keep their current password.
            else:
                user = User(
                    email=email,
                    password_hash=hash_password(password),
                    role="admin",
                    is_active=True,
                )
                db.session.add(user)

            db.session.commit()
            click.echo(f"Administrator ready: {user.email} (id={user.id})")

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models import User

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
