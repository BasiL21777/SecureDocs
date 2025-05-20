from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.document import Document
from app.models.audit_log import AuditLog
from app.admins import admin_bp
import os
from functools import wraps

def admin_required(f):
    @login_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            db.session.add(AuditLog(
                user_id=current_user.id,
                action='admin_access_denied',
                details=f"User {current_user.username} attempted to access admin panel",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('Access denied: Admins only', 'error')
            return redirect(url_for('documents.list'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    user_count = User.query.filter_by(role="User").count()
    document_count = Document.query.count()
    return render_template('admin/dashboard.html', user_count=user_count, document_count=document_count)

@admin_bp.route('/users')
@admin_required
def list_users():
    users = User.query.filter_by(role="User").all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/user/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        role = request.form.get('role')
        is_active = request.form.get('is_active') == 'on'
        if role not in ['User', 'Admin']:
            flash('Invalid role', 'error')
            return redirect(url_for('admin.edit_user', id=id))
        old_role = user.role
        user.role = role
        user.is_active = is_active
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='edit_user',
            details=f"Changed user {user.username}'s role from {old_role} to {role}, active={is_active}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin.list_users'))
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/user/delete/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.list_users'))
    documents = Document.query.filter_by(user_id=user.id).all()
    for doc in documents:
        try:
            if os.path.exists(doc.path):
                os.remove(doc.path)
        except OSError:
            pass
        db.session.delete(doc)
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='delete_user',
        details=f"Deleted user {user.username} (ID: {user.id})",
        ip_address=request.remote_addr
    ))
    db.session.delete(user)
    db.session.commit()
    flash('User and associated documents deleted', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/documents')
@admin_required
def list_documents():
    documents = Document.query.all()
    return render_template('admin/documents.html', documents=documents)

@admin_bp.route('/document/delete/<int:id>', methods=['POST'])
@admin_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    try:
        if os.path.exists(document.path):
            os.remove(document.path)
    except OSError:
        flash('Warning: Could not delete file from disk', 'error')
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='delete_document',
        details=f"Deleted document {document.name} (ID: {id})",
        ip_address=request.remote_addr
    ))
    db.session.delete(document)
    db.session.commit()
    flash('Document deleted successfully', 'success')
    return redirect(url_for('admin.list_documents'))

@admin_bp.route('/logs')
@admin_required
def list_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='view_logs',
        details=f"Viewed audit logs",
        ip_address=request.remote_addr
    ))
    db.session.commit()
    return render_template('admin/logs.html', logs=logs)
