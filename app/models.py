from flask import current_app
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(2000), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.set_password(password)
        self.role = role
        self.set_bio(bio)

    def _peppered(self, password: str) -> str:
        pepper = current_app.config.get("SECURITY_PASSWORD_PEPPER", "")
        return f"{password}{pepper}"

    def set_password(self, password):
        self.password = generate_password_hash(self._peppered(password))

    def check_password(self, password):
        return check_password_hash(self.password, self._peppered(password))

    def _fernet(self):
        key = current_app.config.get("BIO_ENCRYPTION_KEY")
        return Fernet(key)

    def set_bio(self, bio_text: str):
        f = self._fernet()
        self.bio = f.encrypt(bio_text.encode('utf-8')).decode('utf-8')

    def get_bio(self) -> str:
        try:
            f = self._fernet()
            return f.decrypt(self.bio.encode('utf-8')).decode('utf-8')
        except (InvalidToken, ValueError):
            return ""

    def __repr__(self):
        return f'<User {self.username}>'
