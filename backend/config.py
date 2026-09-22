import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///../database/malicious_files.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 0))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(os.path.dirname(__file__), "..", "uploads"))
