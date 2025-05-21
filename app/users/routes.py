from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.document import Document
from app.models.audit_log import AuditLog

user_bp = Blueprint('user', __name__)

@user_bp.route('/dashboard')
@login_required
def dashboard():
    my_documents = Document.query.filter_by(user_id=current_user.id).count()
    return render_template('user/dashboard.html', my_documents=my_documents)

@user_bp.route('/profile')
@login_required
def profile():
    return render_template('user/profile.html', user=current_user)

@user_bp.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if username != current_user.username and User.query.filter_by(username=username).first():
        flash('Username already taken', 'error')
        return redirect(url_for('user.profile'))
    if email != current_user.email and User.query.filter_by(email=email).first():
        flash('Email already in use', 'error')
        return redirect(url_for('user.profile'))

    current_user.username = username
    current_user.email = email
    if password:
        current_user.set_password(password)

    try:
        db.session.commit()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='update_profile',
            details=f"Updated profile: username={username}, email={email}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('Profile updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {str(e)}', 'error')

    return redirect(url_for('user.profile'))
