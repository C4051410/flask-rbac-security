import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf

from config import get_config

csrf = CSRFProtect()
db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())

    db.init_app(app)
    csrf.init_app(app)

    # Register blueprints
    from .routes import main
    from .errors import errors

    app.register_blueprint(main)
    app.register_blueprint(errors)

    # Custom Error Pages (Part I)
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("500.html"), 500

    # Security Headers (Part E)
    @app.after_request
    def add_security_headers(response):
        csp = " ".join(
            [
                "default-src 'self'",
                "script-src 'self' https://cdn.jsdelivr.net",
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
                "img-src 'self' data:",
                "font-src 'self' https://cdn.jsdelivr.net",
                "frame-ancestors 'none'",
            ]
        )
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=()'
        response.headers['Cache-Control'] = 'no-store'
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=generate_csrf)

    # Logging configuration
    log_path = app.config.get("LOG_FILE", "logs/security.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s | ip=%(clientip)s user=%(user)s"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    with app.app_context():
        from .models import User

        db.create_all()

        if not User.query.first():
            users = [
                {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
                {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
                {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
            ]

            for u in users:
                user = User(username=u["username"], password=u["password"], role=u["role"], bio=u["bio"])
                db.session.add(user)

            db.session.commit()

    return app
