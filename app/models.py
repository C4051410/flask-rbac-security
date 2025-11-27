from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    #Primay key for unique identifcation
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Increased size to store password hash
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        #hashes password on creation
        self.username = username
        self.set_password(password) # Hash password on creation
        self.role = role
        self.bio = bio

    def set_password(self, password):
        #Hashes password securely using Werkzeug
        self.password = generate_password_hash(password)

    def check_password(self, password):
        #Verifies inputted password against hash
        return check_password_hash(self.password, password)

    def __repr__(self):
        #debugging without revealing passwords
        return f'<User {self.username}>'