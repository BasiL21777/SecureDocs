from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from app import db
from app.models.document import Document
from app.models.audit_log import AuditLog
import os
import hashlib
import hmac
import base64
from datetime import datetime
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
import io
from flask import current_app

documents_bp = Blueprint('documents', __name__)

@documents_bp.route('/documents', methods=['GET', 'POST'])
@login_required
def documents():
    if request.method == 'POST':
        file = request.files.get('document')

        if not file or file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('documents.documents'))

        # Use AES_KEY from .env
        try:
            key_bytes = base64.b64decode(os.getenv('AES_KEY'))
        except Exception as e:
            flash('Server configuration error', 'error')
            return redirect(url_for('documents.documents'))

        filename = secure_filename(file.filename)
        upload_dir = os.path.join(current_app.root_path, 'Uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)

        # Save file
        file.save(file_path)

        # Calculate file size
        file_size = os.path.getsize(file_path)

        # Get file type (extension without dot)
        file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

        # Calculate HMAC on plaintext
        hmac_key = base64.b64decode(os.getenv('HMAC_KEY'))
        with open(file_path, 'rb') as f:
            file_content = f.read()
            hmac_sha256 = hmac.new(hmac_key, file_content, hashlib.sha256).hexdigest()

        # Encrypt file (mandatory)
        try:
            cipher = AES.new(key_bytes, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file_content)
            with open(file_path, 'wb') as f:
                f.write(nonce + tag + ciphertext)
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(url_for('documents.documents'))

        # Create Document
        document = Document(
            name=filename,
            HMAC_SHA256=hmac_sha256,
            path=file_path,
            type=file_type,
            size=file_size,
            modified=datetime.utcnow(),
            has_secret=True,
            user_id=current_user.id
        )

        try:
            db.session.add(document)
            db.session.commit()
            db.session.add(AuditLog(
                user_id=current_user.id,
                action='upload_document',
                details=f"Uploaded document: {filename} (encrypted)",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('Document uploaded successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading document: {str(e)}', 'error')

        return redirect(url_for('documents.documents'))

    # GET: List documents
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('documents/documents.html', documents=documents)

@documents_bp.route('/download/<int:id>')
@login_required
def download(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='unauthorized_document_access',
            details=f"Attempted to download document ID {id} owned by user {document.user_id}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('Unauthorized access to document', 'error')
        return redirect(url_for('documents.documents'))

    # Handle legacy non-encrypted files
    if not document.has_secret:
        try:
            db.session.add(AuditLog(
                user_id=current_user.id,
                action='download_document',
                details=f"Downloaded document: {document.name} (non-encrypted)",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            return send_file(document.path, download_name=document.name, as_attachment=True)
        except FileNotFoundError:
            flash(f'Document file not found: {document.name}', 'error')
            return redirect(url_for('documents.documents'))
        except OSError as e:
            flash(f'Error reading file: {str(e)}', 'error')
            return redirect(url_for('documents.documents'))

    # Encrypted file: redirect to decrypt
    return redirect(url_for('documents.decrypt', id=id))

@documents_bp.route('/decrypt/<int:id>', methods=['GET', 'POST'])
@login_required
def decrypt(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='unauthorized_document_access',
            details=f"Attempted to decrypt document ID {id} owned by user {document.user_id}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('Unauthorized access to document', 'error')
        return redirect(url_for('documents.documents'))

    # Read file
    try:
        with open(document.path, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        flash(f'Document file not found: {document.name}', 'error')
        return redirect(url_for('documents.documents'))
    except OSError as e:
        flash(f'Error reading file: {str(e)}', 'error')
        return redirect(url_for('documents.documents'))

    # Use AES_KEY
    try:
        decrypt_key = base64.b64decode(os.getenv('AES_KEY'))
    except Exception as e:
        flash('Server configuration error', 'error')
        return redirect(url_for('documents.documents'))

    hmac_key = base64.b64decode(os.getenv('HMAC_KEY'))

    # Validate file content length
    if len(file_content) < 32:
        flash('Invalid file format: File too small', 'error')
        return redirect(url_for('documents.documents'))

    # Decrypt
    try:
        nonce, tag, ciphertext = file_content[:16], file_content[16:32], file_content[32:]
        cipher = AES.new(decrypt_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        flash(f'Decryption failed: {str(e)}', 'error')
        return redirect(url_for('documents.documents'))

    # Verify HMAC
    new_hmac = hmac.new(hmac_key, decrypted_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(new_hmac, document.HMAC_SHA256):
        flash('Integrity check failed: Document may have been tampered with', 'error')
        return redirect(url_for('documents.documents'))

    db.session.add(AuditLog(
        user_id=current_user.id,
        action='download_document',
        details=f"Downloaded document: {document.name} (decrypted)",
        ip_address=request.remote_addr
    ))
    db.session.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=document.name,
        as_attachment=True
    )

@documents_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='unauthorized_document_access',
            details=f"Attempted to delete document ID {id} owned by user {document.user_id}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('Unauthorized access to document', 'error')
        return redirect(url_for('documents.documents'))

    try:
        # Delete file from filesystem
        if os.path.exists(document.path):
            os.remove(document.path)
        # Log deletion
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document',
            details=f"Deleted document: {document.name} (ID: {document.id})",
            ip_address=request.remote_addr
        ))
        # Delete document from database
        db.session.delete(document)
        db.session.commit()
        flash('Document deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document_failed',
            details=f"Failed to delete document: {document.name} (ID: {document.id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to delete document: {str(e)}', 'error')

    return redirect(url_for('documents.documents'))
