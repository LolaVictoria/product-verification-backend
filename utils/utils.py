# utils.py
import uuid, jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify
from functools import wraps
from config import Config
from models.models import find_user_by_id

def hash_password(password: str) -> str:
    return generate_password_hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return check_password_hash(hashed, password)

def generate_jwt(user_id: str, hours: int = 24) -> str:
    payload = {"user_id": str(user_id), "exp": datetime.utcnow() + timedelta(hours=hours)}
    token = jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")
    return token

def decode_jwt(token: str):
    try:
        return jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Missing Authorization header"}), 401
        token = auth.split(" ",1)[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error":"Invalid/expired token"}), 401
        request.user = payload
        return fn(*args, **kwargs)
    return wrapper

def generate_api_key():
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars
