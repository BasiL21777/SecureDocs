from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from werkzeug.routing import BuildError

db = SQLAlchemy()
login_manager = LoginManager()
oauth = OAuth()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    load_dotenv()
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{os.getenv("MYSQL_USER")}:{os.getenv("MYSQL_PASSWORD")}@localhost/secure_docs'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    oauth.init_app(app)
    migrate.init_app(app, db)

    # Jinja filters
    @app.template_filter('number_format')
    def number_format(value):
        try:
            if value is None or not isinstance(value, (int, float)):
                return "0"
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return "0"

    @app.template_filter('format_bytes')
    def format_bytes(bytes):
        try:
            if bytes is None or not isinstance(bytes, (int, float)) or bytes <= 0:
                return "0 B"
            bytes = float(bytes)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes < 1024:
                    return f"{bytes:.2f} {unit}".rstrip('0').rstrip('.')
                bytes /= 1024
            return f"{bytes:.2f} PB".rstrip('0').rstrip('.')
        except (ValueError, TypeError):
            return "0 B"

    @app.template_filter('datetime_format')
    def datetime_format(value):
        try:
            if value is None:
                return "N/A"
            return value.strftime('%Y-%m-%d %H:%M:%S')
        except (AttributeError, ValueError):
            return "N/A"

    @app.template_filter('safe_url_for')
    def safe_url_for(endpoint, **values):
        try:
            return url_for(endpoint, **values)
        except BuildError:
            return None

    from app.models.user import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.auth.routes import auth_bp
    from app.users.routes import user_bp
    from app.documents.routes import documents_bp
    from app.admins.routes import admin_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(documents_bp, url_prefix='/documents')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if current_user.role == 'Admin':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('user.dashboard'))
        return redirect(url_for('auth.login'))

    with app.app_context():
        db.create_all()

    return app
