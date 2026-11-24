from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        remember = bool(request.form.get('remember'))

        user = User.query.filter(
            (User.email.ilike(identifier)) | (User.username.ilike(identifier))
        ).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact your SOC administrator.', 'danger')
                return render_template('auth/login.html')

            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            flash(f'Welcome back, {user.full_name} ({user.role})!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid username/email or password.', 'danger')

    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        role = request.form.get('role', 'SOC Analyst')

        if not username or not email or not full_name or not password:
            flash('All fields are required.', 'warning')
            return render_template('auth/register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return render_template('auth/register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'warning')
            return render_template('auth/register.html')

        if User.query.filter((User.username.ilike(username)) | (User.email.ilike(email))).first():
            flash('A user with that username or email already exists.', 'warning')
            return render_template('auth/register.html')

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role if role in ('Admin', 'SOC Analyst') else 'SOC Analyst',
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in with your credentials.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been securely logged out of the SOC platform.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        new_password = request.form.get('new_password', '').strip()
        current_password = request.form.get('current_password', '').strip()

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('auth/profile.html')

        if full_name:
            current_user.full_name = full_name
        if email:
            existing = User.query.filter(User.email.ilike(email), User.id != current_user.id).first()
            if existing:
                flash('Email is already taken by another account.', 'danger')
                return render_template('auth/profile.html')
            current_user.email = email

        if new_password:
            if len(new_password) < 8:
                flash('New password must be at least 8 characters.', 'warning')
                return render_template('auth/profile.html')
            current_user.set_password(new_password)

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html')

@auth_bp.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Access restricted to SOC Administrators.', 'danger')
        return redirect(url_for('dashboard.index'))
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('auth/users.html', users=all_users)

@auth_bp.route('/users/<int:user_id>/toggle-role', methods=['POST'])
@login_required
def toggle_role(user_id):
    if not current_user.is_admin:
        flash('Access restricted to SOC Administrators.', 'danger')
        return redirect(url_for('dashboard.index'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot modify your own administrative role.', 'warning')
        return redirect(url_for('auth.users'))

    user.role = 'Admin' if user.role == 'SOC Analyst' else 'SOC Analyst'
    db.session.commit()
    flash(f"Updated role for {user.username} to {user.role}.", 'success')
    return redirect(url_for('auth.users'))

@auth_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_status(user_id):
    if not current_user.is_admin:
        flash('Access restricted to SOC Administrators.', 'danger')
        return redirect(url_for('dashboard.index'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('auth.users'))

    user.is_active = not user.is_active
    db.session.commit()
    status_str = "activated" if user.is_active else "deactivated"
    flash(f"Account for {user.username} has been {status_str}.", 'info')
    return redirect(url_for('auth.users'))
