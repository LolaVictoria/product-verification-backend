# auth.py
from flask import Blueprint, request, jsonify
from models.schemas import SignupSchema, LoginSchema
from models.models import create_user, find_user_by_email, create_api_key
from utils.utils import hash_password, generate_jwt, generate_api_key
from marshmallow import ValidationError

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    try:
        data = SignupSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    if find_user_by_email(data["email"]):
        return jsonify({"error":"email already registered"}), 400

    user = create_user(
        email=data["email"], 
        password_hash=hash_password(data["password"]), 
        role=data["role"]
    )
    key = generate_api_key()
    create_api_key(str(user["_id"]), key, label="default")
    token = generate_jwt(str(user["_id"]))
    return jsonify({"token": token, "api_key": key}), 201


@bp.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    try:
        data = LoginSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    user = find_user_by_email(data["email"])
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    from utils import verify_password
    if not verify_password(data["password"], user["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    token = generate_jwt(str(user["_id"]))
    return jsonify({"token": token}), 200
