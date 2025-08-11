# api.py
from flask import Blueprint, request, jsonify
from extensions import mongo, limiter
from config import Config
from models.models import find_product_by_serial, find_apikey_by_key, log_api_usage
from datetime import datetime

bp = Blueprint("api", __name__, url_prefix="/api")

# apply limiter specifically for verify endpoint using RATE_LIMIT from config
verify_limit = Config.RATE_LIMIT

@bp.route("/verify", methods=["GET"])
@limiter.limit(verify_limit)
def verify():
    api_key = request.args.get("api_key") or request.headers.get("X-API-KEY")
    serial = request.args.get("serial")
    if not api_key or not serial:
        return jsonify({"error":"api_key and serial required"}), 400

    ak = find_apikey_by_key(api_key)
    if not ak or ak.get("revoked"):
        return jsonify({"error":"invalid or revoked api_key"}), 401

    user = mongo.db.users.find_one({"_id": ak["user_id"]}) if ak else None
    log_api_usage(str(ak["_id"]), str(user["_id"]) if user else None, "verify", request.remote_addr)

    product = find_product_by_serial(serial)
    if not product:
        return jsonify({"verified": False}), 200

    return jsonify({"verified": True, "product": {"serial": product["serial"], "name": product["name"], "verified": product.get("verified", False), "registered_at": product.get("registered_at").isoformat() if product.get("registered_at") else None}}), 200
