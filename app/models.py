from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Increased size to store password hash
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.set_password(password) # Hash password on creation
        self.role = role
        self.bio = bio

    def set_password(self, password):
        """Hashes the password and sets the column value."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks a password against the stored hash."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'




