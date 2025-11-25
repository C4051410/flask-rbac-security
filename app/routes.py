import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from app import db
from app.models import User

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # FIX: Use ORM for secure retrieval and password check (no SQL Injection)
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        # FIX: Check password against hash (Secure Authentication/Cryptography)
        if user and user.check_password(password):
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login credentials are invalid, please try again')
    return render_template('login.html')


@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        bio = request.form['bio']
        role = request.form.get('role', 'user')

        # Input Validation (Part A)
        if not (6 <= len(password) <= 64):
            flash('Password must be between 6 and 64 characters long.', 'error')
            return render_template('register.html')

        if len(bio) > 500:
            print("--- DEBUG: Bio too long, attempting to flash error! ---")
            flash('Biography cannot exceed 500 characters.', 'error')
            return render_template('register.html')

        # Check for existing username
        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            flash('That username is already taken.', 'error')
            return render_template('register.html')

        # FIX: Use ORM for insertion (User.__init__ handles hashing)
        new_user = User(username=username, password=password, role=role, bio=bio)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')


@main.route('/admin-panel')
def admin():
    # Authorization check (Part F)
    if 'user' not in session or session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')


@main.route('/moderator')
def moderator():
    # Authorization check (Part F)
    if 'user' not in session or session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')


@main.route('/user-dashboard')
def user_dashboard():
    # Authorization check (Part F)
    if 'user' not in session or session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        # FIX: Fetch user and use check_password
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        # Enforce: current password must be valid for user (using hash check)
        if not user or not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        # FIX: Hash and update the password
        user.set_password(new_password)
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')
@main.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    session.pop('bio', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.home'))