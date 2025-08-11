# models.py
from extensions import mongo
from bson import ObjectId
from datetime import datetime

# Users: store api keys in separate collection apikeys to allow multiple keys
# users: { _id, email, password_hash, role, created_at }
# apikeys: { _id, user_id, key, created_at, revoked, label }
# products: { _id, serial, name, manufacturer_id, blockchain_tx, registered_at, verified }
# api_usage: { _id, api_key_id, user_id, endpoint, ip, timestamp }

def create_user(email: str, password_hash: str, role: str = "developer"):
    doc = {"email": email, "password_hash": password_hash, "role": role, "created_at": datetime.utcnow()}
    res = mongo.db.users.insert_one(doc)
    return mongo.db.users.find_one({"_id": res.inserted_id})

def find_user_by_email(email: str):
    return mongo.db.users.find_one({"email": email})

def find_user_by_id(user_id: str):
    try:
        return mongo.db.users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None

# apikeys
def create_api_key(user_id: str, key: str, label: str = None):
    doc = {"user_id": user_id, "key": key, "label": label, "revoked": False, "created_at": datetime.utcnow()}
    res = mongo.db.apikeys.insert_one(doc)
    return mongo.db.apikeys.find_one({"_id": res.inserted_id})

def find_apikey_by_key(key: str):
    return mongo.db.apikeys.find_one({"key": key})

def list_apikeys_for_user(user_id: str):
    return list(mongo.db.apikeys.find({"user_id": user_id}))

def revoke_apikey(apikey_id: str):
    mongo.db.apikeys.update_one({"_id": ObjectId(apikey_id)}, {"$set": {"revoked": True}})
    return mongo.db.apikeys.find_one({"_id": ObjectId(apikey_id)})

# products
def insert_product(serial: str, name: str, manufacturer_id: str, blockchain_tx: str = None):
    doc = {"serial": serial, "name": name, "manufacturer_id": manufacturer_id, "blockchain_tx": blockchain_tx, "registered_at": datetime.utcnow(), "verified": bool(blockchain_tx)}
    res = mongo.db.products.insert_one(doc)
    return mongo.db.products.find_one({"_id": res.inserted_id})

def find_product_by_serial(serial: str):
    return mongo.db.products.find_one({"serial": serial})

def list_products_by_manufacturer(manufacturer_id: str):
    return list(mongo.db.products.find({"manufacturer_id": manufacturer_id}))

# usage
def log_api_usage(api_key_id: str, user_id: str, endpoint: str, ip: str = None):
    mongo.db.api_usage.insert_one({"api_key_id": api_key_id, "user_id": user_id, "endpoint": endpoint, "ip": ip, "timestamp": datetime.utcnow()})
