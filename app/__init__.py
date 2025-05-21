from flask import Flask, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from datetime import datetime
from werkzeug.routing import BuildError

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Jinja filters
    @app.template_filter('number_format')
    def number_format(value):
        if value is None or not isinstance(value, (int, float)):
            return "0"
        return f"{int(value):,}"

    @app.template_filter('format_bytes')
    def format_bytes(bytes):
        if bytes is None or not isinstance(bytes, (int, float)):
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    @app.template_filter('datetime_format')
    def datetime_format(value):
        return value.strftime('%Y-%m-%d %H:%M:%S') if value else 'N/A'

    @app.template_filter('safe_url_for')
    def safe_url_for(endpoint, **values):
        try:
            return url_for(endpoint, **values)
        except BuildError:
            return None

    from app.auth import auth_bp
    from app.documents import documents_bp
    from app.users import user_bp
    from app.admins import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(documents_bp, url_prefix='/documents')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    from app.models.user import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        from app.models.document import Document
        from app.models.user import User
        from app.models.audit_log import AuditLog
        db.create_all()

    return app
