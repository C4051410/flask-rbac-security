import os
from datetime import timedelta


def _get_env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


class Config:
    DEBUG = False
    TESTING = False

    SECRET_KEY = _get_env("SECRET_KEY", "dev-secret-key-change-me")
    SECURITY_PASSWORD_PEPPER = _get_env("SECURITY_PASSWORD_PEPPER", "dev-pepper")
    BIO_ENCRYPTION_KEY = _get_env(
        "BIO_ENCRYPTION_KEY",
        # Fernet key must be 32 url-safe base64-encoded bytes; this fallback is for dev only
        "3_0eA_sO7N7ugz0nOo_SriQoypC0Bm6MmMRLhtW4yqE=",
    )

    SQLALCHEMY_DATABASE_URI = _get_env("DATABASE_URL", "sqlite:///site.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _get_env("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # Logging
    LOG_FILE = _get_env("LOG_FILE", "logs/security.log")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"


def get_config():
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    return DevelopmentConfig
