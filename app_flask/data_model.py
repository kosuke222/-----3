from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = "roles"
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)    # ハッシュ化
    virustotal_api_key = db.Column(db.Text)                     # 暗号化
    malwarebazaar_api_key = db.Column(db.Text)                     # 暗号化
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    reports = db.relationship("Report", backref="user", lazy=True)
    @property
    def id(self):
        return self.user_id

class UserRole(db.Model):
    __tablename__ = "user_roles"
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True, nullable=False)

class Report(db.Model):
    """レポート情報を格納するテーブルに対応するモデル"""
    __tablename__ = "reports"

    report_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    malware_family = db.Column(db.String(255), nullable=True)
    hash_sha256 = db.Column(db.String(64), nullable=False)
    report_markdown = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Report {self.report_id} (SHA256: {self.hash_sha256[:10]}...)>"