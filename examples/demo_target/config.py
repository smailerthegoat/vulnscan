import os

SECRET_KEY = "k9#mQ2vL!x7Rp4Tz8Wc1-notes-prod-session"
JWT_SECRET = os.environ["JWT_SECRET"]
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///notes.db")
