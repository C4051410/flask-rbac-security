
import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from app import db
from app.models import User

main = Blueprint('main', __name__)


@main.route('/')
def home():
    #Public homepage
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        #Using SQLAlchemy ORM prevents SQL injections
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        #Ensures passwords are hashed
        if user and user.check_password(password):
            # Stores user info server side
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio
            return redirect(url_for('main.dashboard'))
        else:
            #Feedback without revealing wrong credentials
            flash('Login credentials are invalid, please try again')
    return render_template('login.html')


@main.route('/dashboard')
def dashboard():
    #access check for authenticated users
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

        #logic to prevent weak passwords and excessive bio
        if not (6 <= len(password) <= 64):
            flash('Password must be between 6 and 64 characters long.', 'error')
            return render_template('register.html')

        if len(bio) > 500:
            print("--- DEBUG: Bio too long, attempting to flash error! ---")
            flash('Biography cannot exceed 500 characters.', 'error')
            return render_template('register.html')

        #Check for existing username
        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            flash('That username is already taken.', 'error')
            return render_template('register.html')

        #hashes password automatically
        new_user = User(username=username, password=password, role=role, bio=bio)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')


@main.route('/admin-panel')
def admin():
    #only admin role can access
    if 'user' not in session or session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')


@main.route('/moderator')
def moderator():
    #only moderator role can access
    if 'user' not in session or session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')




@main.route('/user-dashboard')
def user_dashboard():
    #only standard user can access
    if 'user' not in session or session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic login state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        #Fetch user and use check_password
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        #verify current password using hash
        if not user or not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        #new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        #Hash and update the password
        user.set_password(new_password)
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')
@main.route('/logout')
def logout():
    #clear all session data
    session.pop('user', None)
    session.pop('role', None)
    session.pop('bio', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.home'))

