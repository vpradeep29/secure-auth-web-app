from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from app import db
from app.forms import LoginForm, RegistrationForm
from app.models import AuditLog, User
from app.security.authorization import admin_required
from app.security.passwords import hash_password, verify_password

main = Blueprint('main', __name__)

def record_event(event_type, description, user_id=None):
    db.session.add(AuditLog(user_id=user_id, event_type=event_type, description=description, ip_address=request.remote_addr))

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash('Unable to create an account with those details.', 'error')
            return render_template('register.html', form=form), 400
        user = User(email=email, password_hash=hash_password(form.password.data))
        db.session.add(user)
        db.session.flush()
        record_event('REGISTRATION', 'New user account registered.', user.id)
        db.session.commit()
        flash('Account created. You can now sign in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is None:
            record_event('LOGIN_FAILURE', 'Failed login for an unknown account.')
            db.session.commit()
            flash('Invalid email or password.', 'error')
            return render_template('login.html', form=form), 401
        if not user.is_active or not verify_password(user.password_hash, form.password.data):
            record_event('LOGIN_FAILURE', 'Failed login or inactive account.', user.id)
            db.session.commit()
            flash('Invalid email or password.', 'error')
            return render_template('login.html', form=form), 401
        session.clear()
        login_user(user, remember=False, fresh=True)
        session.permanent = True
        record_event('LOGIN_SUCCESS', 'User logged in successfully.', user.id)
        db.session.commit()
        flash('Signed in successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('login.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():
    recent_events = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template('dashboard.html', recent_events=recent_events)

@main.route('/admin')
@login_required
@admin_required
def admin():
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'inactive_users': User.query.filter_by(is_active=False).count(),
        'total_events': AuditLog.query.count(),
        'login_successes': AuditLog.query.filter_by(event_type='LOGIN_SUCCESS').count(),
        'login_failures': AuditLog.query.filter_by(event_type='LOGIN_FAILURE').count(),
        'registrations': AuditLog.query.filter_by(event_type='REGISTRATION').count(),
    }
    recent_events = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
    users = User.query.order_by(User.created_at.desc()).limit(100).all()
    return render_template('admin.html', **stats, recent_events=recent_events, users=users)

@main.route('/admin/users/<int:user_id>/status', methods=['POST'])
@login_required
@admin_required
def update_user_status(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash('You cannot deactivate your own administrator account.', 'error')
        return redirect(url_for('main.admin'))
    user.is_active = request.form.get('is_active') == 'true'
    record_event('ADMIN_USER_STATUS_CHANGED', f'Administrator changed account status for user ID {user.id}.', current_user.id)
    db.session.commit()
    flash('User status updated.', 'success')
    return redirect(url_for('main.admin'))

@main.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id = current_user.id
    record_event('LOGOUT', 'User logged out successfully.', user_id)
    db.session.commit()
    logout_user()
    session.clear()
    flash('You have been signed out.', 'success')
    return redirect(url_for('main.home'))

@main.app_errorhandler(403)
def forbidden(_error):
    return render_template('error.html', code=403, message='You do not have permission to access this page.'), 403

@main.app_errorhandler(404)
def not_found(_error):
    return render_template('error.html', code=404, message='The requested page could not be found.'), 404
