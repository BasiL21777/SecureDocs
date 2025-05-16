from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
import os

db =SQLAlchemy()
login_manager=LoginManager()

def create_app():
    load_dotenv()
    app=Flask(__name__)
    app.config['SECRET_KEY']=os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI']=os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view='auth.login'


    from app.auth import auth_bp
    from app.documents import documents_bp
    from app.users import user_bp
    # from admins import admin_bp

    app.register_blueprint(auth_bp,url_prefix='/auth')
    app.register_blueprint(documents_bp, url_prefix='/documents')
    app.register_blueprint(user_bp, url_prefix='/user')
    # app.register_blueprint(admin_bp, url_prefix='/admin')

    from app.models.user import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        from app.models import document , user
        db.create_all()

        return app
