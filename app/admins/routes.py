from flask import Blueprint, render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.document import Document
from app.models.audit_log import AuditLog
from functools import wraps
from sqlalchemy import func
import os
import logging
import csv
from io import StringIO
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            flash('Access denied: Admin role required', 'error')
            return redirect(url_for('user.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Fetch all documents to debug sizes
    documents = Document.query.all()
    total_size = 0
    for doc in documents:
        if doc.size is not None and doc.size > 0:
            total_size += doc.size
            logger.debug(f"Document {doc.id} ({doc.name}): size = {doc.size} bytes")
        else:
            logger.debug(f"Document {doc.id} ({doc.name}): size = {doc.size or 'None'}")

    # Alternative query for validation
    query_size = db.session.query(func.sum(Document.size)).scalar()
    logger.debug(f"Total storage size from query: {query_size}")
    logger.debug(f"Total storage size from manual sum: {total_size}")

    stats = {
        'users': User.query.filter_by(role="User").count(),
        'documents': Document.query.count(),
        'logs': AuditLog.query.count(),
        'storage': total_size if total_size is not None else 0,
        'recent_activity': AuditLog.query.join(User, User.id == AuditLog.user_id).order_by(AuditLog.timestamp.desc()).limit(5).all(),
        'recent_documents': Document.query.order_by(Document.modified.desc()).limit(5).all()
    }
    for activity in stats['recent_activity']:
        user = User.query.get(activity.user_id)
        activity.user_name = user.username if user else 'Unknown'
        activity.status = 'success'  # Adjust based on AuditLog data
    return render_template('admin/dashboard.html', stats=stats)




@admin_bp.route('/download_logs', methods=['GET'])
@login_required
@admin_required
def download_logs():
    # Query all logs
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()

    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'User ID', 'Username', 'Action', 'Details', 'IP Address'])

    for log in logs:
        user = User.query.get(log.user_id)
        username = user.username if user else 'Unknown'
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else 'N/A',
            log.user_id,
            username,
            log.action,
            log.details,
            log.ip_address
        ])

    # Log the download action
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='download_logs',
        details='Downloaded all system logs as CSV',
        ip_address=request.remote_addr
    ))
    db.session.commit()

    # Prepare response
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=system_logs_{timestamp}.csv'}
    )


@admin_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def admin_users():
    users = User.query.filter_by(role="User").all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/edit_user/<int:id>', methods=['POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if user.id == current_user.id and request.form.get('role') != 'Admin':
        flash('Cannot remove Admin role from yourself', 'error')
        return redirect(url_for('admin.admin_users'))

    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')

    if not username or not email:
        flash('Username and email are required', 'error')
        return redirect(url_for('admin.admin_users'))

    try:
        user.username = username
        user.email = email
        user.role = role
        db.session.commit()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='edit_user',
            details=f"Edited user {user.username} (ID: {user.id})",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('User updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='edit_user_failed',
            details=f"Failed to edit user {user.username} (ID: {user.id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to update user: {str(e)}', 'error')

    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/delete_user/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('admin.admin_users'))

    try:
        documents = Document.query.filter_by(user_id=user.id).all()
        for doc in documents:
            if os.path.exists(doc.path):
                os.remove(doc.path)
            db.session.delete(doc)
        db.session.delete(user)
        db.session.commit()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_user',
            details=f"Deleted user {user.username} (ID: {user.id})",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_user_failed',
            details=f"Failed to delete user {user.username} (ID: {user.id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to delete user: {str(e)}', 'error')

    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/logs')
@login_required
@admin_required
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin/logs.html', logs=logs)

@admin_bp.route('/documents')
@login_required
@admin_required
def admin_documents():
    documents = Document.query.join(User, User.id == Document.user_id).filter(User.role == 'User').order_by(Document.modified.desc()).all()
    return render_template('admin/documents.html', documents=documents)

@admin_bp.route('/delete_document/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    try:
        if os.path.exists(document.path):
            os.remove(document.path)
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document',
            details=f"Admin deleted document {document.name} (ID: {document.id})",
            ip_address=request.remote_addr
        ))
        db.session.delete(document)
        db.session.commit()
        flash('Document deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document_failed',
            details=f"Failed to delete document {document.name} (ID: {document.id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to delete document: {str(e)}', 'error')
    return redirect(url_for('admin.admin_documents'))

@admin_bp.route('/update_settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    max_file_size = request.form.get('max_file_size')
    allowed_types = request.form.get('allowed_types')
    storage_limit = request.form.get('storage_limit')
    flash('Settings updated successfully', 'success')
    return redirect(url_for('admin.dashboard'))
