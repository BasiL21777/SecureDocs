from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required, current_user
from app import db
from app.models.document import Document
from app.models.audit_log import AuditLog
import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename

documents_bp = Blueprint('documents', __name__)
BASE_PATH = r'D:\Learn Flask\Final_DI\SecureDocs'
UPLOAD_FOLDER = os.path.join(BASE_PATH, 'app', 'Uploads')
STATIC_UPLOAD_FOLDER = os.path.join(BASE_PATH, 'app', 'static', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_hmac(file_data, key):
    return base64.b64encode(hashlib.sha256(file_data + key).digest()).decode()

@documents_bp.route('/documents')
@login_required
def documents():
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('documents/documents.html', documents=documents)

@documents_bp.route('/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('documents.documents'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('documents.documents'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_data = file.read()
        key = base64.b64decode(os.getenv('AES_KEY'))
        hmac_key = base64.b64decode(os.getenv('HMAC_KEY'))
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = iv + cipher.encrypt(padded_data)
            hmac = get_hmac(encrypted_data, hmac_key)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            document = Document(
                name=filename,
                HMAC_SHA256=hmac,
                path=file_path,
                type=filename.rsplit('.', 1)[1].lower(),
                size=len(file_data),
                has_secret=True,
                user_id=current_user.id
            )
            db.session.add(document)
            db.session.commit()
            db.session.add(AuditLog(
                user_id=current_user.id,
                action='upload_document',
                details=f"Uploaded document {filename}",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('File uploaded successfully', 'success')
        except Exception as e:
            db.session.rollback()
            db.session.add(AuditLog(
                user_id=current_user.id,
                action='upload_document_failed',
                details=f"Failed to upload document {filename}: {str(e)}",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash(f'Failed to upload file: {str(e)}', 'error')
    else:
        flash('File type not allowed', 'error')
    return redirect(url_for('documents.documents'))

@documents_bp.route('/download/<int:id>')
@login_required
def download_document(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        flash('Access denied', 'error')
        return redirect(url_for('documents.documents'))
    try:
        if not os.path.exists(document.path):
            raise FileNotFoundError(f"File not found at {document.path}")
        key = base64.b64decode(os.getenv('AES_KEY'))
        with open(document.path, 'rb') as f:
            file_data = f.read()
        hmac_key = base64.b64decode(os.getenv('HMAC_KEY'))
        stored_hmac = document.HMAC_SHA256
        computed_hmac = get_hmac(file_data, hmac_key)
        if stored_hmac != computed_hmac:
            raise ValueError('HMAC verification failed')
        if len(file_data) < 16:
            raise ValueError('File data too short for decryption')
        cipher = AES.new(key, AES.MODE_CBC, file_data[:16])
        try:
            decrypted_data = unpad(cipher.decrypt(file_data[16:]), AES.block_size)
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{document.name}")
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='download_document',
            details=f"Downloaded document {document.name} (ID: {id})",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        return send_file(temp_path, as_attachment=True, download_name=document.name)
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='download_document_failed',
            details=f"Failed to download document {document.name} (ID: {id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to download document: {str(e)}', 'error')
        return redirect(url_for('documents.documents'))
    finally:
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

@documents_bp.route('/documents/preview/<int:id>')
@login_required
def preview_document(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        flash('Access denied', 'error')
        return redirect(url_for('documents.documents'))
    try:
        if not os.path.exists(document.path):
            raise FileNotFoundError(f"File not found at {document.path}")
        if document.type.lower() == 'pdf':
            key = base64.b64decode(os.getenv('AES_KEY'))
            with open(document.path, 'rb') as f:
                file_data = f.read()
            hmac_key = base64.b64decode(os.getenv('HMAC_KEY'))
            stored_hmac = document.HMAC_SHA256
            computed_hmac = get_hmac(file_data, hmac_key)
            if stored_hmac != computed_hmac:
                raise ValueError('HMAC verification failed')
            if len(file_data) < 16:
                raise ValueError('File data too short for decryption')
            cipher = AES.new(key, AES.MODE_CBC, file_data[:16])
            try:
                decrypted_data = unpad(cipher.decrypt(file_data[16:]), AES.block_size)
            except ValueError as e:
                raise ValueError(f"Decryption failed: {str(e)}")
            os.makedirs(STATIC_UPLOAD_FOLDER, exist_ok=True)
            temp_filename = f"preview_{id}_{document.name}"
            static_path = os.path.join(STATIC_UPLOAD_FOLDER, temp_filename)
            with open(static_path, 'wb') as f:
                f.write(decrypted_data)
            # preview_url = url_for('static', filename=f'uploads/{temp_filename}')
            preview_url = url_for('static', filename=f'uploads\\Book_Store_Management_System.pdf')
        else:
            preview_url = None
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='preview_document',
            details=f"Previewed document {document.name} (ID: {id})",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        return render_template('documents/preview.html', name=document.name, preview_url=preview_url, document_id=id)
    except Exception as e:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='preview_document_failed',
            details=f"Failed to preview document {document.name} (ID: {id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to preview document: {str(e)}', 'error')
        return redirect(url_for('documents.documents'))

@documents_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_document(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id and current_user.role != 'Admin':
        flash('Access denied', 'error')
        return redirect(url_for('documents.documents'))
    try:
        if os.path.exists(document.path):
            os.remove(document.path)
        temp_filename = f"preview_{id}_{document.name}"
        static_path = os.path.join(STATIC_UPLOAD_FOLDER, temp_filename)
        if os.path.exists(static_path):
            os.remove(static_path)
        db.session.delete(document)
        db.session.commit()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document',
            details=f"Deleted document {document.name} (ID: {id})",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash('Document deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='delete_document_failed',
            details=f"Failed to delete document {document.name} (ID: {id}): {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'Failed to delete document: {str(e)}', 'error')
    return redirect(url_for('documents.documents'))
