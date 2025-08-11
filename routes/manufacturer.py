# manufacturer.py
from flask import Blueprint, request, jsonify
from utils import jwt_required
from schemas import ProductRegisterSchema
from models import find_user_by_id, find_product_by_serial, insert_product
from marshmallow import ValidationError

bp = Blueprint("manufacturer", __name__, url_prefix="/manufacturer")

@bp.route("/register", methods=["POST"])
@jwt_required
def register_product():
    try:
        data = ProductRegisterSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    user = find_user_by_id(request.user["user_id"])
    if not user or user.get("role") != "manufacturer":
        return jsonify({"error":"only manufacturers can register products"}), 403

    if find_product_by_serial(data["serial"]):
        return jsonify({"error":"serial already registered"}), 400

    product = insert_product(serial=data["serial"], name=data["name"], manufacturer_id=str(user["_id"]), blockchain_tx=data.get("blockchain_tx"))
    return jsonify({"product": {"serial": product["serial"], "name": product["name"], "registered_at": product["registered_at"].isoformat(), "verified": product["verified"]}}), 201

@bp.route("/my-products", methods=["GET"])
@jwt_required
def my_products():
    user = find_user_by_id(request.user["user_id"])
    prods = list_products_by_manufacturer(str(user["_id"]))
    out = []
    for p in prods:
        out.append({"serial": p["serial"], "name": p["name"], "verified": p.get("verified", False), "registered_at": p.get("registered_at").isoformat() if p.get("registered_at") else None})
    return jsonify({"products": out})
