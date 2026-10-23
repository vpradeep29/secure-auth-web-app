import click
from getpass import getpass

from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from config import Config


db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message_category = 'error'


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    migrate.init_app(app, db, compare_type=True)
    csrf.init_app(app)
    login_manager.init_app(app)

    from app.models import AuditLog, User  # noqa: F401
    from app.routes import main
    app.register_blueprint(main)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
        if app.config.get('COOKIE_SECURE'):
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        return response

    @app.cli.command('init-db')
    def init_db():
        '''Create tables directly for a disposable local/test database.'''
        with app.app_context():
            db.create_all()
        click.echo('Database tables created. Prefer flask db upgrade for managed databases.')

    @app.cli.command('create-admin')
    @click.option('--email', prompt=True)
    def create_admin(email):
        '''Create an administrator or promote an existing account.'''
        from app.models import User
        from app.security.passwords import hash_password
        from app.security.validators import password_strength_error

        email = email.strip().lower()
        if not email or '@' not in email:
            raise click.ClickException('Enter a valid email address.')

        with app.app_context():
            existing = User.query.filter_by(email=email).first()
            if existing:
                existing.role = 'admin'
                existing.is_active = True
                db.session.commit()
                click.echo(f'Promoted existing account {existing.email} to admin; its current password is unchanged.')
                return

            password = getpass('Admin password (12+ characters): ')
            confirmation = getpass('Confirm password: ')
            if len(password) < 12 or len(password) > 128:
                raise click.ClickException('Password must contain between 12 and 128 characters.')
            if password != confirmation:
                raise click.ClickException('Passwords do not match.')
            weakness = password_strength_error(password)
            if weakness:
                raise click.ClickException(weakness)

            user = User(email=email, password_hash=hash_password(password), role='admin', is_active=True)
            db.session.add(user)
            db.session.commit()
            click.echo(f'Administrator created: {user.email} (id={user.id})')

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
