from app import db
from datetime import datetime

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for anonymous users
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # Supports IPv4 and IPv6

    user = db.relationship('User', backref='audit_logs', lazy=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.user.username if self.user else 'Anonymous'} from {self.ip_address}>"
