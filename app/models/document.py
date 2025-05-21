from app import db
from datetime import datetime

class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    HMAC_SHA256 = db.Column(db.String(64), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # e.g., 'pdf', 'docx'
    size = db.Column(db.Integer, nullable=False)  # Size in bytes
    modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    has_secret = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', back_populates='documents')

    def __repr__(self):
        return f"<Document {self.name}>"
