# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    SECRET_KEY = os.getenv("SECRET_KEY", "change_me")
    JWT_SECRET = os.getenv("JWT_SECRET", "change_me_jwt")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/product_verification_db")
    RATE_LIMIT = os.getenv("RATE_LIMIT", "100/hour")
    # blockchain
    CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
    CONTRACT_ABI_PATH = os.getenv("CONTRACT_ABI_PATH")
    PROVIDER_URL = os.getenv("PROVIDER_URL")
    PRIVATE_KEY = os.getenv("PRIVATE_KEY")
