import os
from cryptography.fernet import Fernet

class Config:
    DEBUG = True

    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-key-change-me"
    BIO_ENCRYPTION_KEY = os.environ.get("BIO_ENCRYPTION_KEY") or b"s7-eMmr_4NtDFMSTl1i0d0aX5qUysBTY7E5QR9zv-Io="

    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
