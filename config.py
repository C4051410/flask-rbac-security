import os

class Config:
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-key-change-me"

    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
