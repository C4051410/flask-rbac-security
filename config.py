class Config:
    DEBUG = False
    TESTING = False


    SECRET_KEY = "j151095n10n51095n108hn15u9n1"

    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
