from app import db
from datetime import datetime

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    HMAC_SHA256 = db.Column(db.String(64), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    modified = db.Column(db.DateTime, default=datetime.utcnow)
    has_secret = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Document {self.name}>'
