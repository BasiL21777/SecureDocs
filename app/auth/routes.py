from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.models.audit_log import AuditLog
from datetime import datetime

auth_bp = Blueprint('auth', __name__, template_folder='templates/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('documents.upload'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('auth.register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful, please log in', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('documents.upload'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            db.session.add(AuditLog(
                user_id=user.id,
                action='login',
                details=f"User {username} logged in",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('Logged in successfully', 'success')
            return redirect(url_for('documents.upload'))
        else:
            db.session.add(AuditLog(
                user_id=user.id if user else None,
                action='login_failed',
                details=f"Failed login attempt for username {username}",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('Invalid username, password, or inactive account', 'error')
            return redirect(url_for('auth.login'))
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    db.session.add(AuditLog(
        user_id=user_id,
        action='logout',
        details=f"User {username} logged out",
        ip_address=request.remote_addr
    ))
    db.session.commit()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
