from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.models.audit_log import AuditLog
from werkzeug.security import generate_password_hash
from authlib.integrations.flask_client import OAuth
from flask import current_app
import os
import re
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__)
oauth = OAuth(current_app)

# Configure GitHub OAuth
oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('documents.documents'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('auth.register'))
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include an uppercase letter, '
                  'a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('auth.register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful, please log in', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html')

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user.dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['pending_2fa_user_id'] = user.id
            return redirect(url_for('auth.setup_verify_2fa', username=username))
        flash('Invalid username or password', 'error')
    return render_template('auth/login.html')

@auth_bp.route('/2fa/setup-verify/<username>', methods=['GET', 'POST'])
def setup_verify_2fa(username):
    user = User.query.filter_by(username=username).first()
    if not user or user.id != session.get('pending_2fa_user_id'):
        flash('Invalid 2FA verification attempt', 'error')
        return redirect(url_for('auth.login'))

    qr_code = None
    if not user.totp_secret:
        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.session.commit()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='SecureDocs')
        qr = qrcode.make(uri)
        img = io.BytesIO()
        qr.save(img)
        img.seek(0)
        qr_code = base64.b64encode(img.getvalue()).decode('utf-8')

    if request.method == 'POST':
        user_code = request.form.get('code')
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(user_code):
            login_user(user)
            db.session.add(AuditLog(
                user_id=user.id,
                action='2fa_verified',
                details=f"User {username} verified 2FA",
                ip_address=request.remote_addr
            ))
            db.session.commit()
            flash('2FA verified successfully', 'success')
            session.pop('pending_2fa_user_id', None)
            if user.role == 'Admin':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('user.dashboard'))
        flash('Invalid or expired 2FA code', 'error')

    return render_template('auth/2fa_setup_verify.html', username=username, qr_code=qr_code)

@auth_bp.route('/github/login')
def github_login():
    if current_user.is_authenticated:
        return redirect(url_for('user.dashboard'))
    return oauth.github.authorize_redirect(url_for('auth.github_callback', _external=True))

@auth_bp.route('/github/callback')
def github_callback():
    try:
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        github_user = resp.json()
        github_id = str(github_user['id'])
        email = github_user.get('email')
        username = github_user.get('login')
        user = User.query.filter_by(github_id=github_id).first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                user.github_id = github_id
            else:
                user = User(
                    username=username,
                    email=email or f"{github_id}@github.com",
                    github_id=github_id,
                    role='User'
                )
                user.set_password(generate_password_hash(os.urandom(16).hex()))
                db.session.add(user)
            db.session.commit()
        session['pending_2fa_user_id'] = user.id
        return redirect(url_for('auth.setup_verify_2fa', username=user.username))
    except Exception as e:
        db.session.add(AuditLog(
            user_id=None,
            action='github_login_failed',
            details=f"GitHub login failed: {str(e)}",
            ip_address=request.remote_addr
        ))
        db.session.commit()
        flash(f'GitHub login failed: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='logout',
        details=f"User {current_user.username} logged out",
        ip_address=request.remote_addr
    ))
    db.session.commit()
    logout_user()
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
