class Config:
    DEBUG = False
    TESTING = False


    SECRET_KEY = "replace-this-with-a-long-random-string-123!@#"

    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
