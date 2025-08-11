import os
from datetime import timedelta
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change-me-to-a-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              f"sqlite:///{os.path.join(BASE_DIR, 'forum.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif'}
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
