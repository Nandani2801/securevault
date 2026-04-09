import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey123")
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://securevault:securevault@localhost:5432/securevault"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/uploads")
    MAX_CONTENT_LENGTH = None
    MAX_LOGIN_ATTEMPTS = 9999
    LOGGING_ENABLED = False
    WTF_CSRF_ENABLED = False