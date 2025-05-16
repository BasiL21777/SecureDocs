from flask import Blueprint , render_template , request ,redirect,url_for,flash,send_file
from flask_login import login_required , current_user
from app.models.document import Document
from app import db
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad ,unpad
import hashlib ,hmac ,base64 ,io
from datetime import datetime

documents_bp=Blueprint('documents',__name__,template_folder='templates/documents')

UPLOADS_DIR=os.path.join(os.path.dirname(__file__),'../uploads')
os.makedirs(UPLOADS_DIR,exist_ok=True)

AES_KEY=base64.b64decode(os.getenv('AES_KEY'))
HMAC_KEY=base64.b64decode(os.getenv('HMAC_KEY'))

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('Invalid file type! Only PDF, DOCX, and TXT are allowed.', 'error')
            return redirect(request.url)
        file_content = file.read()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        hmac_sha256 = hmac.new(HMAC_KEY, file_content, hashlib.sha256).hexdigest()

        cipher = AES.new(AES_KEY, AES.MODE_CBC)
        iv = cipher.IV
        padded_data = pad(file_content, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        encrypted_content = iv + encrypted_data  # Prepend IV for decryption

        filename = f"{current_user.id}_{datetime.utcnow().timestamp()}_{file.filename}"
        file_path = os.path.normpath(os.path.join(UPLOADS_DIR, filename))

        try:
            with open(file_path, 'wb') as f:
                f.write(encrypted_content)
        except OSError as e:
            flash(f'Failed to save file: {str(e)}', 'error')
            return redirect(request.url)

        document = Document(
            name=file.filename,
            HMAC_SHA256=hmac_sha256,
            path=file_path,
            user_id=current_user.id,
            has_secret=False  # Use server key
        )
        db.session.add(document)
        db.session.commit()
        flash('Document uploaded successfully', 'success')
        return redirect(url_for('documents.list'))
    return render_template('documents/upload.html')



@documents_bp.route('/list')
@login_required
def list():
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('documents/list.html', documents=documents)


@documents_bp.route('/download/<int:id>')
@login_required
def download(id):
    document = Document.query.get_or_404(id)
    if document.user_id != current_user.id:
        flash('Unauthorized access to document', 'error')
        return redirect(url_for('documents.list'))
    try:
        with open(document.path, 'rb') as f:
            encrypted_content = f.read()
    except FileNotFoundError:
        flash('Document file not found', 'error')
        return redirect(url_for('documents.list'))
    except OSError as e:
        flash(f'Error reading file: {str(e)}', 'error')
        return redirect(url_for('documents.list'))

    iv = encrypted_content[:16]
    encrypted_data = encrypted_content[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except ValueError as e:
        flash('Decryption failed: Invalid padding', 'error')
        return redirect(url_for('documents.list'))

    new_hmac = hmac.new(HMAC_KEY, decrypted_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(new_hmac, document.HMAC_SHA256):
        flash('Integrity check failed: Document may have been tampered with', 'error')
        return redirect(url_for('documents.list'))

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=document.name,
        as_attachment=True
    )
