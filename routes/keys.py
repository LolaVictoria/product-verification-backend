# keys.py
from flask import Blueprint, request, jsonify
from utils import jwt_required, generate_api_key
from models import find_user_by_id, create_api_key, list_apikeys_for_user, revoke_apikey, find_apikey_by_key
from bson import ObjectId

bp = Blueprint("keys", __name__, url_prefix="/keys")

@bp.route("/generate", methods=["POST"])
@jwt_required
def generate_key():
    user_id = request.user["user_id"]
    user = find_user_by_id(user_id)
    if not user:
        return jsonify({"error":"user not found"}), 404
    body = request.json or {}
    label = body.get("label")
    key = generate_api_key()
    apidoc = create_api_key(str(user["_id"]), key, label=label)
    return jsonify({"api_key_id": str(apidoc["_id"]), "key": key, "label": label}), 201

@bp.route("/list", methods=["GET"])
@jwt_required
def list_keys():
    user_id = request.user["user_id"]
    keys = list_apikeys_for_user(user_id)
    out = []
    for k in keys:
        out.append({"id": str(k["_id"]), "key": k["key"], "label": k.get("label"), "revoked": k.get("revoked", False), "created_at": k.get("created_at")})
    return jsonify(out), 200

@bp.route("/revoke/<key_id>", methods=["POST"])
@jwt_required
def revoke(key_id):
    # key_id is apikey document id
    revoked = revoke_apikey(key_id)
    return jsonify({"revoked": True, "key_id": key_id}), 200
