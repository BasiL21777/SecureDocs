from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.audit_log import AuditLog
from werkzeug.security import generate_password_hash
import os
from datetime import datetime

user_bp = Blueprint('user', __name__)

@user_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('user/dashboard.html', user=current_user)

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
    profile_image = request.files.get('profile_image')

    if not username or not email:
        flash('Username and email are required', 'danger')
        return redirect(url_for('user.profile'))

    try:
        # Check for duplicate username or email
        if User.query.filter(User.username == username, User.id != current_user.id).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('user.profile'))
        if User.query.filter(User.email == email, User.id != current_user.id).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('user.profile'))

        # Update user fields
        current_user.username = username
        current_user.email = email
        if password:
            current_user.password_hash = generate_password_hash(password)

        # Handle profile image upload
        if profile_image and profile_image.filename:
            # Validate file extension
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
            ext = os.path.splitext(profile_image.filename)[1].lower()
            if ext not in allowed_extensions:
                flash('Invalid image format. Use JPG, JPEG, PNG, or GIF', 'danger')
                return redirect(url_for('user.profile'))

            # Create profiles directory if it doesn't exist
            upload_dir = os.path.join('app', 'static', 'images', 'profiles')
            os.makedirs(upload_dir, exist_ok=True)

            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{current_user.id}_{timestamp}{ext}"
            file_path = os.path.join(upload_dir, filename)

            # Save file
            profile_image.save(file_path)

            # Update profile_image path (relative to static)
            current_user.profile_image = f"/static/images/profiles/{filename}"

        db.session.commit()

        # Log the update
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='update_profile',
            details=f"Updated profile for {username}",
            ip_address=request.remote_addr
        ))
        db.session.commit()

        flash('Profile updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='update_profile_failed',
            details=f"Failed to update profile for {username}: {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to update profile: {str(e)}', 'danger')

    return redirect(url_for('user.profile'))
