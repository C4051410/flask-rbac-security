import logging
import re
import secrets
from datetime import datetime, timedelta

import bleach
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    current_app,
)

from app import db
from app.models import User

main = Blueprint('main', __name__)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_BLACKLIST = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!"}
ALLOWED_TAGS = ["b", "i", "u", "em", "strong", "a", "p", "ul", "ol", "li", "br"]
ALLOWED_ATTRS = {"a": ["href", "title"]}


def _log_event(level: str, message: str, user=None):
    extra = {
        "clientip": request.remote_addr,
        "user": getattr(user, "username", None) or session.get("user_id") or "anonymous",
    }
    log_level = getattr(logging, level.upper(), logging.INFO)
    current_app.logger.log(log_level, message, extra=extra)


def validate_email(email: str) -> bool:
    return bool(email and EMAIL_REGEX.match(email))


def validate_password(username: str, password: str) -> str:
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    if username.lower() in password.lower():
        return "Password cannot contain the username."
    if password in PASSWORD_BLACKLIST:
        return "Password is blacklisted."
    if re.search(r"(.)\1{2,}", password):
        return "Password cannot contain repeated sequences."
    return ""


def sanitize_bio(bio: str) -> str:
    cleaned = bleach.clean(bio or "", tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    return cleaned.strip()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def require_recent_login():
    last_auth = session.get("last_auth")
    if not last_auth:
        return False
    try:
        last = datetime.fromisoformat(last_auth)
    except ValueError:
        return False
    return datetime.utcnow() - last < timedelta(minutes=10)


@main.route('/')
def home():
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['role'] = user.role
            session['nonce'] = secrets.token_hex(16)
            session['last_auth'] = datetime.utcnow().isoformat()
            _log_event('info', 'login_success', user)
            return redirect(url_for('main.dashboard'))

        _log_event('warning', 'login_failed', user)
        flash('Login credentials are invalid, please try again')
    return render_template('login.html')


@main.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for('main.login'))
    bio_html = sanitize_bio(user.get_bio())
    return render_template('dashboard.html', username=user.username, bio=bio_html)


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        bio = request.form.get('bio', '')

        if not validate_email(username):
            flash('A valid email address is required.', 'error')
            return render_template('register.html')

        password_error = validate_password(username, password)
        if password_error:
            flash(password_error, 'error')
            return render_template('register.html')

        cleaned_bio = sanitize_bio(bio)
        if len(cleaned_bio) > 1000:
            flash('Biography cannot exceed 1000 characters.', 'error')
            return render_template('register.html')

        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            flash('That username is already taken.', 'error')
            return render_template('register.html')

        new_user = User(username=username, password=password, role='user', bio=cleaned_bio)
        db.session.add(new_user)
        db.session.commit()

        _log_event('info', 'registration_success', new_user)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')


def _enforce_role(required_role: str):
    user = current_user()
    if not user or user.role != required_role:
        _log_event('warning', f'access_denied_{required_role}')
        abort(403)
    return user


@main.route('/admin-panel')
def admin():
    _enforce_role('admin')
    return render_template('admin.html')


@main.route('/moderator')
def moderator():
    _enforce_role('moderator')
    return render_template('moderator.html')


@main.route('/user-dashboard')
def user_dashboard():
    user = _enforce_role('user')
    return render_template('user_dashboard.html', username=user.username)


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    user = current_user()
    if not user:
        abort(403)

    if request.method == 'POST':
        if not require_recent_login():
            flash('Please reauthenticate before changing your password.', 'error')
            return redirect(url_for('main.login'))

        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        if not user.check_password(current_password):
            _log_event('warning', 'password_change_failed_bad_current', user)
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        password_error = validate_password(user.username, new_password)
        if password_error:
            flash(password_error, 'error')
            return render_template('change_password.html')

        user.set_password(new_password)
        db.session.commit()
        session['last_auth'] = datetime.utcnow().isoformat()
        _log_event('info', 'password_changed', user)

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')


@main.route('/logout', methods=['POST'])
def logout():
    user = current_user()
    _log_event('info', 'logout', user)
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.home'))
