# app.py - Optimized Flask Application with CORS
from bson import ObjectId
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
from flask_cors import CORS, cross_origin
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from web3 import Web3
import hashlib
import re
import traceback

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Enhanced CORS Configuration
CORS(app, 
     origins=[
         'http://localhost:3000',
         'http://localhost:5173',
         'https://your-frontend-domain.com'
     ],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
     allow_headers=[
         'Content-Type', 
         'Authorization', 
         'X-Requested-With',
         'X-API-Key',
         'Accept',
         'Origin',
         'Cache-Control',
         'Pragma'
     ],
     supports_credentials=True,
     expose_headers=['Authorization', 'X-Total-Count'],
     max_age=86400
)

# Initialize Web3
try:
    w3 = Web3(Web3.HTTPProvider(os.getenv('BLOCKCHAIN_RPC_URL')))
except:
    w3 = None
    print("Warning: Web3 not initialized")

# Import helper functions
from helper_functions import (
    # Database functions
    get_user_by_email, get_user_by_id, create_user, update_user_verification_status, get_db_connection,
    get_product_by_serial, create_product, get_all_products, get_products_by_manufacturer,
    get_pending_manufacturers, create_api_key, get_api_keys_by_user, validate_api_key, update_user,
    get_primary_email, get_primary_wallet, is_valid_email, is_valid_wallet_address, email_exists_globally,
    wallet_exists_globally, get_current_company_name, get_verified_wallets, generate_verification_token,
    send_email_verification, initiate_wallet_verification, format_user_profile, validate_product_data,
    validate_ownership_transfer, get_ownership_history_by_serial, create_ownership_transfer,
    log_verification_attempt, blacklist_token,
    
    # Blockchain functions
    verify_on_blockchain, register_product_blockchain, verify_manufacturer_on_blockchain,
    check_manufacturer_authorization, get_blockchain_product_details, verify_product_on_blockchain,
    store_registration_transaction, register_device_blockchain,
    
    # Utility functions
    hash_password, verify_password, format_product_response, format_user_response,
    get_current_utc,
    
    # Validation functions
    validate_user_registration, validate_product_data, ValidationError, 
    AuthenticationError, BlockchainError,
    
    # New verification classes
    ElectronicsAuthenticator, DatabaseManager
)

# ===============================
# CORS UTILITIES
# ===============================
# Enhanced CORS Configuration
CORS(app, 
     origins=[
         'http://localhost:3000',
         'http://localhost:5173',
         'https://your-frontend-domain.com'
     ],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
     allow_headers=[
         'Content-Type', 
         'Authorization', 
         'X-Requested-With',
         'X-API-Key',
         'Accept',
         'Origin',
         'Cache-Control',
         'Pragma',
         'headers'
     ],
     supports_credentials=True,
     expose_headers=['Authorization', 'X-Total-Count'],
     max_age=86400
)

def add_cors_headers(response):
    """Add comprehensive CORS headers to any response"""
    # Get the origin from the request
    origin = request.headers.get('Origin')
    
    # List of allowed origins
    allowed_origins = [
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'https://your-frontend-domain.com'
    ]
    
    # Set origin if it's in allowed list, otherwise use first allowed origin
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5173'
    
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Requested-With,X-API-Key,Accept,Origin,Cache-Control,Pragma, headers'
    response.headers['Access-Control-Expose-Headers'] = 'Authorization,X-Total-Count'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'
    
    return response
def create_cors_response(data, status_code=200):
    """Helper function to create CORS-enabled responses"""
    response = make_response(jsonify(data), status_code)
    return add_cors_headers(response)

@app.after_request
def after_request(response):
    """Apply CORS headers to all responses"""
    return add_cors_headers(response)

@app.before_request
def handle_preflight():
    """Handle preflight OPTIONS requests"""
    if request.method == "OPTIONS":
        response = make_response()
        response = add_cors_headers(response)
        return response
# ===============================
# AUTHENTICATION DECORATORS
# ===============================

def validate_token(token, secret_key):
    """Validate JWT token and return user info"""
    if not token:
        return None, None, {'message': 'Token is missing!'}, 401
    
    if token.startswith('Bearer '):
        token = token[7:]
        
    try:
        data = jwt.decode(token, secret_key, algorithms=['HS256'])
        if 'sub' not in data or 'role' not in data:
            return None, None, {'message': 'Invalid token: missing required fields'}, 401
        return ObjectId(data['sub']), data['role'], None, None
    except jwt.ExpiredSignatureError:
        return None, None, {'message': 'Token has expired!'}, 401
    except jwt.InvalidTokenError:
        return None, None, {'message': 'Token is invalid!'}, 401
    except Exception:
        return None, None, {'message': 'Token validation failed'}, 401

def token_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return create_cors_response({'message': 'Invalid token format'}, 401)
        
        if not token:
            return create_cors_response({'message': 'Token is missing'}, 401)
        
        try:
            # Check if token is blacklisted
            db = get_db_connection()
            blacklisted = db.blacklisted_tokens.find_one({"token": token})
            if blacklisted:
                return create_cors_response({'message': 'Token has been revoked'}, 401)
            
            # Verify token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['sub']
            current_user_role = data.get('role')
            
        except jwt.ExpiredSignatureError:
            return create_cors_response({'message': 'Token has expired'}, 401)
        except jwt.InvalidTokenError:
            return create_cors_response({'message': 'Invalid token'}, 401)
        except Exception:
            return create_cors_response({'message': 'Token verification failed'}, 401)
        
        return f(current_user_id, current_user_role, *args, **kwargs)
    return decorated

def token_required_with_roles(allowed_roles):
    """Decorator for routes requiring specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            user_id, user_role, error, status = validate_token(token, app.config['SECRET_KEY'])
            if error:
                return create_cors_response(error, status)
            if allowed_roles and user_role not in allowed_roles:
                return create_cors_response({'message': f'Access denied: requires one of {allowed_roles}'}, 403)
            return f(user_id, user_role, *args, **kwargs)
        return decorated
    return decorator

def api_key_required(f):
    """Decorator for API key authentication"""
    @wraps(f)
    def decorator(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        
        if not api_key:
            return create_cors_response({'message': 'API key is required'}, 401)
            
        key_data = validate_api_key(api_key)
        if not key_data:
            return create_cors_response({'message': 'Invalid API key'}, 401)
            
        return f(*args, **kwargs)
    return decorator

# ===============================
# STATIC FILES
# ===============================

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ===============================
# PUBLIC VERIFICATION ROUTES
# ===============================

@app.route('/verify/<serial_number>', methods=['GET'])
@token_required_with_roles(allowed_roles=['manufacturer', 'customer'])
def verify_product_public(current_user_id, current_user_role, serial_number):
    """Enhanced verification with blockchain check"""
    try:
        db = get_db_connection()
        
        if db is None:
            print("Database connection failed")
            return create_cors_response({"authentic": False, "message": "Database connection failed"}, 500)
            
        print("Database connection established")
        
        # Debug: Show sample serials (remove in production)
        try:
            all_serials = list(db.products.find({}, {"serial_number": 1}).limit(5))
            print(f"Sample serial numbers in DB: {all_serials}")
        except Exception as e:
            print(f"Error fetching sample serials: {e}")
        
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Database lookup with error handling
        try:
            product = db.products.find_one({"serial_number": serial_number})
            print(f"Database query result: {product is not None}")
            if product:
                print(f"Product found: {product.get('brand', 'Unknown')} {product.get('model', 'Unknown')}")
        except Exception as e:
            print(f"Database query error: {e}")
            return create_cors_response({"authentic": False, "message": "Database query error"}, 500)
        
        if product:
            print(f"Product found in DB. Blockchain verified flag: {product.get('blockchain_verified')}")
            
            if product.get("blockchain_verified"):
                # Try blockchain verification with proper error handling
                try:
                    blockchain_result = verify_product_on_blockchain(serial_number)
                    print(f"Blockchain result: {blockchain_result}")
                except Exception as e:
                    print(f"Blockchain verification failed: {e}")
                    blockchain_result = {"verified": False, "error": str(e)}
                
                if not blockchain_result.get("verified"):
                    result = {
                        "authentic": False,
                        "message": "Product found in database but blockchain verification failed",
                        "source": "database_only",
                        "blockchain_error": blockchain_result.get("error"),
                        "serialNumber": serial_number
                    }
                else:
                    result = {
                        "authentic": True,
                        "serialNumber": serial_number,
                        "brand": product.get("brand"),
                        "model": product.get("model"),
                        "deviceType": product.get("device_type"),
                        "color": product.get("color"),
                        "storage": product.get("storage_data"),
                        "manufacturerName": product.get("manufacturer_name"),
                        "source": "blockchain",
                        "blockchain_verified": True,
                        "ownership_history": product.get("ownership_history", []),
                        "message": "Product verified on blockchain",
                        "blockchain_proof": blockchain_result.get("proof"),
                        "registered_at": product.get("registered_at"),
                        "created_at": product.get("created_at"),
                        "verification_timestamp": datetime.now(timezone.utc)
                    }
            else:
                result = {
                    "authentic": True,
                    "serialNumber": serial_number,
                    "brand": product.get("brand"),
                    "model": product.get("model"),
                    "deviceType": product.get("device_type"),
                    "color": product.get("color"),
                    "storage": product.get("storage_data"),
                    "manufacturerName": product.get("manufacturer_name"),
                    "source": "database",
                    "blockchain_verified": False,
                    "message": "Product verified in database only"
                }
        else:
            print("Product not found in DB, checking blockchain...")
            
            # Check blockchain directly with error handling
            try:
                blockchain_result = verify_product_on_blockchain(serial_number)
                print(f"Blockchain check result: {blockchain_result}")
            except Exception as e:
                print(f"Blockchain verification failed: {e}")
                blockchain_result = {"verified": False, "error": str(e)}

            if blockchain_result.get("verified"):
                tx_hash = blockchain_result.get("transaction_hash")
                contract_address = blockchain_result.get("contract_address")
                network = blockchain_result.get("network", "sepolia")
    
                explorer_urls = {
                    "ethereum": "https://etherscan.io",
                    "sepolia": "https://sepolia.etherscan.io",
                    "polygon": "https://polygonscan.com", 
                    "bsc": "https://bscscan.com"
                }
                
                base_url = explorer_urls.get(network, "https://sepolia.etherscan.io")
    
                result = {
                    "authentic": True,
                    "serialNumber": serial_number,
                    "source": "blockchain",
                    "blockchain_verified": True,
                    "message": "Product verified on blockchain",
                    "blockchain_proof": {
                        "transaction_hash": tx_hash,
                        "contract_address": contract_address or "0x07c05F17f53ff83d0b5F469bFA0Cb36bDc9eA950",
                        "network": network,
                        "explorer_links": {
                            "transaction": f"{base_url}/tx/{tx_hash}" if tx_hash else None,
                            "contract": f"{base_url}/address/{contract_address or '0x07c05F17f53ff83d0b5F469bFA0Cb36bDc9eA950'}"
                        }
                    },
                    "verification_timestamp": datetime.now(timezone.utc).isoformat()
                }
            else:
                result = {
                    "authentic": False,
                    "message": "Product not found in database or blockchain",
                    "source": "not_found",
                    "serialNumber": serial_number
                }
        
        # Log verification attempt
        try:
            log_verification_attempt(db, {
                "serial_number": serial_number,
                "authentic": result["authentic"],
                "source": result["source"],
                "user_id": current_user_id,
                "user_role": current_user_role,
                "user_ip": user_ip,
                "timestamp": datetime.now(timezone.utc)
            })
        except Exception as e:
            print(f"Logging failed: {e}")
        
        print(f"Returning result: {result}")
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Verification route error: {e}")
        traceback.print_exc()
        return create_cors_response({
            "authentic": False, 
            "message": "Verification service error",
            "error": str(e)
        }, 500)
    
@app.route('/verify-batch', methods=['POST'])
@token_required_with_roles(['manufacturer', 'customer'])
def verify_batch_public(current_user_id, current_user_role):
    """Enhanced public batch verification endpoint"""
    try:
        data = request.get_json()
        serial_numbers = data.get('serialNumbers', [])
        
        if not serial_numbers or len(serial_numbers) > 10:
            return create_cors_response({
                "error": "Please provide 1-10 serial numbers"
            }, 400)
        
        db = get_db_connection()
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        results = []
        total_verified = 0
        
        for serial_number in serial_numbers:
            product = db.products.find_one({"serial_number": serial_number})
            
            if product:
                result = {
                    "serialNumber": serial_number,
                    "authentic": True,
                    "brand": product.get("brand"),
                    "model": product.get("model"),
                    "deviceType": product.get("device_type"),
                    "manufacturerName": product.get("manufacturer_name"),
                    "source": "blockchain" if product.get("blockchain_verified") else "database"
                }
                total_verified += 1
            else:
                result = {
                    "serialNumber": serial_number,
                    "authentic": False,
                    "source": "not_found",
                    "message": "Product not found"
                }
            
            results.append(result)
            
            # Log each verification
            log_verification_attempt(db, {
                "serial_number": serial_number,
                "authentic": result["authentic"],
                "source": result.get("source", "unknown"),
                "user_ip": user_ip,
                "timestamp": datetime.now(timezone.utc)
            })
        
        return create_cors_response({
            "status": "success",
            "results": results,
            "total_verified": total_verified,
            "total_checked": len(results)
        }, 200)
        
    except Exception as e:
        print(f"Batch verification error: {e}")
        return create_cors_response({"error": "Batch verification failed"}, 500)
    
@app.route('/stats', methods=['GET'])
def get_verification_stats():
    """Get system verification statistics"""
    try:
        db = get_db_connection()
        
        # Count total products
        total_devices = db.products.count_documents({})
        blockchain_devices = db.products.count_documents({"blockchain_verified": True})
        
        # Count verification logs
        total_verifications = db.verification_logs.count_documents({}) if hasattr(db, 'verification_logs') else 0
        
        # Calculate authenticity rate
        authentic_verifications = db.verification_logs.count_documents({"authentic": True}) if hasattr(db, 'verification_logs') else 0
        authenticity_rate = int((authentic_verifications / total_verifications * 100)) if total_verifications > 0 else 0
        
        stats = {
            "total_devices": total_devices,
            "blockchain_devices": blockchain_devices,
            "total_verifications": total_verifications,
            "authenticity_rate": authenticity_rate
        }
        
        return create_cors_response(stats, 200)
        
    except Exception as e:
        print(f"Stats error: {e}")
        return create_cors_response({
            "total_devices": 0,
            "blockchain_devices": 0,
            "total_verifications": 0,
            "authenticity_rate": 0
        }, 500)

@app.route('/sample-data', methods=['GET'])
@token_required_with_roles(['manufacturer', 'customer'])
def get_sample_data(current_user_id, current_user_role):
    """Get sample serial numbers for testing"""
    try:
        db = get_db_connection()
        
        # Get authentic devices from database
        authentic_products = list(db.products.find(
            {"blockchain_verified": True}
        ).limit(5))
        
        database_products = list(db.products.find(
            {"blockchain_verified": False}
        ).limit(5))
        
        # Some fake serials for testing
        fake_serials = ["FAKE001", "INVALID123", "COUNTERFEIT", "NOTREAL999", "BOGUS456"]
        
        sample_data = {
            "authentic": {
                "blockchain": [product["serial_number"] for product in authentic_products],
                "database": [product["serial_number"] for product in database_products]
            },
            "counterfeit": fake_serials
        }
        
        return create_cors_response(sample_data, 200)
        
    except Exception as e:
        print(f"Sample data error: {e}")
        return create_cors_response({
            "authentic": {"blockchain": [], "database": []},
            "counterfeit": ["FAKE001", "INVALID123"]
        }, 500)

@app.route('/device-details/<serial_number>', methods=['GET'])
@token_required_with_roles(['manufacturer', 'customer'])
def get_device_details(current_user_id, current_user_role, serial_number):
    """Get detailed device information"""
    try:
        db = get_db_connection()
        product = db.products.find_one({"serial_number": serial_number})
        
        if product:
            # Convert ObjectId to string
            product['_id'] = str(product['_id'])
            
            details = {
                "status": "success",
                "serial_number": product.get("serial_number"),
                "serialNumber": product.get("serial_number"),
                "brand": product.get("brand"),
                "model": product.get("model"),
                "device_type": product.get("device_type"),
                "deviceType": product.get("device_type"),
                "storage_data": product.get("storage_data"),
                "storage": product.get("storage_data"),
                "color": product.get("color"),
                "manufacturer_name": product.get("manufacturer_name"),
                "manufacturerName": product.get("manufacturer_name"),
                "registration_type": product.get("registration_type"),
                "blockchain_verified": product.get("blockchain_verified", False),
                "transaction_hash": product.get("transaction_hash"),
                "registered_at": product.get("registered_at"),
                "created_at": product.get("created_at")
            }
            
            return create_cors_response(details, 200)
        else:
            return create_cors_response({
                "status": "not_found",
                "error": "Device details not found"
            }, 404)
            
    except Exception as e:
        print(f"Device details error: {e}")
        return create_cors_response({"error": "Could not load device details"}, 500)

@app.route('/ownership-history/<serial_number>', methods=['GET'])
@token_required_with_roles(['manufacturer', 'customer'])
def get_ownership_history(user_id, user_role, serial_number):
    """Get ownership history for a verified product"""
    try:
        db = get_db_connection()
        product = db.products.find_one({"serial_number": serial_number})
        if not product:
            return create_cors_response({
                "status": "not_found",
                "message": "Product not found"
            }, 404)

        ownership_history = product.get("ownership_history", [])
        
        data = []
        for transfer in ownership_history:
            data.append({
                "transfer_reason": transfer.get("notes", "Initial Registration"),
                "from": transfer.get("previous_owner", "Manufacturer"),
                "to": transfer.get("owner_name"),
                "transfer_date": transfer.get("transfer_date", product.get("registered_at")),
                "sale_price": transfer.get("sale_price", 0),
                "transaction_hash": transfer.get("transaction_hash", product.get("transaction_hash"))
            })

        # If no ownership history exists, create default entry
        if not data:
            data.append({
                "transfer_reason": "Initial Registration",
                "previous_owner": "Manufacturer",
                "new_owner": product.get("current_owner", product.get("manufacturer_wallet")),
                "transfer_date": product.get("registered_at"),
                "sale_price": 0,
                "transaction_hash": product.get("transaction_hash")
            })

        return create_cors_response({
            "status": "success",
            "serial_number": serial_number,
            "history": data
        }, 200)

    except Exception as e:
        print(f"Ownership history error: {e}")
        return create_cors_response({"error": "Could not load ownership history"}, 500)
    
@app.route('/log-verification', methods=['POST'])
def log_verification_attempt():
    """Log verification attempts for analytics"""
    try:
        data = request.get_json()
        db = get_db_connection()
        
        log_entry = {
            "serial_number": data.get("serial_number"),
            "authentic": data.get("authentic", False),
            "timestamp": datetime.now(timezone.utc),
            "user_ip": request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            "user_agent": data.get("user_agent", "")
        }
        
        db.verification_logs.insert_one(log_entry)
        return create_cors_response({"status": "logged"}, 200)
        
    except Exception as e:
        print(f"Verification logging error: {e}")
        return create_cors_response({"error": "Logging failed"}, 500)
    
@app.route('/seed-data', methods=['GET'])
def seed_sample_data():
    """Seed database with sample verification data"""
    try:
        db = get_db_connection()
        db_manager = DatabaseManager(db)
        
        result = db_manager.seed_sample_data()
        
        return create_cors_response({
            "status": "success",
            "message": result["message"],
            "details": result
        }, 200)
        
    except Exception as e:
        print(f"Seed data error: {e}")
        return create_cors_response({"error": "Could not seed sample data"}, 500)

# ===============================
# AUTHENTICATION ROUTES
# ===============================

@app.route('/auth/login', methods=['POST', 'OPTIONS'])
def login():
    """Login with enhanced CORS handling"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        # Add debug logging
        print(f"Login request from origin: {request.headers.get('Origin')}")
        print(f"Request headers: {dict(request.headers)}")
        
        data = request.get_json()
        if not data:
            print("No JSON data received")
            return create_cors_response({"error": "No JSON data provided"}, 400)
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return create_cors_response({"error": "Email and password required"}, 400)
        
        # Get user from database
        user = get_user_by_email(email)
        if not user:
            return create_cors_response({"error": "Invalid credentials"}, 401)
        
        # Check password
        if not verify_password(user["password_hash"], password):
            return create_cors_response({"error": "Invalid credentials"}, 401)
        
        # Create JWT token
        token_payload = {
            'sub': str(user["_id"]),
            'role': user["role"],
            'email': user["primary_email"],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # Format user data
        user_data = {
            "id": str(user["_id"]),
            "role": user["role"],
            "primary_email": user["primary_email"],
            "emails": user.get("emails", []),
            "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
            "updated_at": user.get("updated_at").isoformat() if user.get("updated_at") else None,
        }
        
        # Add role-specific fields
        if user["role"] == "manufacturer":
            user_data.update({
                "verification_status": user.get("verification_status", "pending"),
                "current_company_name": user.get("current_company_name"),
                "company_names": user.get("company_names", []),
                "primary_wallet": user.get("primary_wallet"),
                "verified_wallets": user.get("verified_wallets", []),
                "wallet_addresses": user.get("wallet_addresses", [])
            })
        elif user["role"] == "customer":
            user_data.update({
                "verification_status": "customer"
            })
        
        # Remove None values
        user_data = {k: v for k, v in user_data.items() if v is not None}
        
        response_data = {
            "status": "success",
            "token": token,
            "user": user_data,
            "message": "Login successful"
        }
        
        print(f"Login successful for user: {email}")
        return create_cors_response(response_data, 200)
        
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return create_cors_response({"error": "Internal server error"}, 500)


@app.route('/auth/signup', methods=['POST', 'OPTIONS'])
def signup():
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        data = request.get_json()
        
        # Validate input data
        validate_user_registration(data)
        
        # Check if user already exists
        existing_user = get_user_by_email(data["email"])
        if existing_user:
            return create_cors_response({"error": "User with this email already exists"}, 400)
        
        # Create user data
        user_data = {
            "emails": [data["email"]],  
            "primary_email": data["email"],  
            "password_hash": hash_password(data["password"]),
            "role": data["role"],
            "created_at": get_current_utc(),
        }

        # For manufacturers
        if data["role"] == "manufacturer":
            user_data.update({
                "wallet_addresses": [data["wallet_address"]],
                "primary_wallet": data["wallet_address"],
                "company_names": [data.get("company_name", "")],
                "current_company_name": data.get("company_name", ""),
                "verification_status": "pending",
                "verified_wallets": []
            })
        
        # Create user
        user_id = create_user(user_data)
        
        return create_cors_response({
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id
        }, 201)
        
    except ValidationError as e:
        return create_cors_response({"error": str(e)}, 400)
    except Exception as e:
        print(f"Signup error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

# ===============================
# PROFILE
# ===============================

@app.route('/manufacturer/profile', methods=['GET', 'OPTIONS'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def get_manufacturer_profile(current_user_id, current_user_role):
    """Get manufacturer profile details"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
        
        profile_data = format_user_profile(user)
        return create_cors_response({
            "status": "success",
            "user": profile_data
        }, 200)
        
    except Exception as e:
        print(f"Manufacturer profile error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)


@app.route('/customer/profile', methods=['GET', 'OPTIONS'])
@token_required_with_roles(allowed_roles=['customer'])
def get_customer_profile(current_user_id, current_user_role):
    """Get customer profile details"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
        
        profile_data = format_user_profile(user)
        
        return create_cors_response({
            "status": "success",
            "user": profile_data
        }, 200)
        
    except Exception as e:
        print(f"Customer profile error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)
# ===============================
# PROFILE
# ===============================
# MANUFACTURER ROUTES
# ===============================

@app.route('/manufacturer/register-product', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def register_manufacturer_product(current_user_id, current_user_role):
    """Register a new product (database only, frontend handles blockchain)"""
    try:
        data = request.get_json()
        
        # Validate required fields - handle both field name formats
        serial_number = data.get('serialNumber') or data.get('serial_number')
        brand = data.get('brand')
        model = data.get('model')
        device_type = data.get('deviceType') or data.get('device_type')
        
        if not all([serial_number, brand, model, device_type]):
            return create_cors_response({
                "error": "Missing required fields: serialNumber, brand, model, deviceType"
            }, 400)
        
        # Get and validate manufacturer
        manufacturer = get_user_by_id(current_user_id)
        if not manufacturer:
            return create_cors_response({"error": "Manufacturer not found"}, 404)
        
        if manufacturer.get("verification_status") != "verified":
            return create_cors_response({
                "error": "Your account is not verified by admin yet"
            }, 403)
        
        # Validate manufacturer data
        primary_wallet = manufacturer.get('primary_wallet')
        if not primary_wallet:
            return create_cors_response({
                "error": "No wallet address found. Please add a wallet first."
            }, 400)
        
        current_company_name = manufacturer.get('current_company_name')
        if not current_company_name:
            return create_cors_response({"error": "Company name not set"}, 400)
        
        # Check for duplicate serial number
        existing_product = get_product_by_serial(serial_number)
        if existing_product:
            return create_cors_response({
                "error": "Product with this serial number already exists"
            }, 400)
        
        # Prepare product data
        product_data = {
            "_id": ObjectId(),
            "serial_number": serial_number,
            "brand": brand,
            "model": model,
            "device_type": device_type,
            "storage_data": data.get('storageData', ''),
            "color": data.get('color', ''),
            "batch_number": data.get('batchNumber', f"BATCH-{int(datetime.now(timezone.utc).timestamp())}"),
            "name": f"{brand} {model}",
            "category": device_type,
            "description": f"{brand} {model} - {data.get('storageData', '')} {data.get('color', '')}",
            "manufacturer_wallet": data.get('manufacturerWallet', primary_wallet),
            "specification_hash": data.get('specificationHash', ''),
            "registration_type": data.get('registration_type', 'blockchain_pending'),
            "manufacturer_id": current_user_id,
            "manufacturer_name": current_company_name,
            "wallet_address": primary_wallet,
            "blockchain_verified": False,
            "ownership_history": [],
            "registered_at": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        # Save to database
        db = get_db_connection()
        result = db.products.insert_one(product_data)
        product_id = str(result.inserted_id)
        
        return create_cors_response({
            "status": "success",
            "success": True,
            "message": "Product saved to database successfully",
            "product_id": product_id,
            "serial_number": serial_number
        }, 201)
        
    except Exception as e:
        print(f"Product registration error: {e}")
        return create_cors_response({
            "error": f"Internal server error: {str(e)}"
        }, 500)

@app.route('/manufacturer/dashboard-stats', methods=['GET'])
@token_required_with_roles(['manufacturer'])
def get_manufacturer_dashboard_stats(current_user_id, current_user_role):
    """Get dashboard statistics for manufacturer"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        manufacturer_wallet = user.get('primary_wallet')
        if not manufacturer_wallet:
            return create_cors_response({'error': 'No wallet found'}, 400)
        
        db = get_db_connection()
        
        # Count products by status
        base_query = {"manufacturer_wallet": manufacturer_wallet}
        total_products = db.products.count_documents(base_query)
        blockchain_products = db.products.count_documents({
            **base_query, "registration_type": "blockchain_confirmed"
        })
        pending_products = db.products.count_documents({
            **base_query, "registration_type": "blockchain_pending"
        })
        
        # Count verifications for manufacturer's products
        manufacturer_serials = list(db.products.find(base_query, {"serial_number": 1}))
        serial_numbers = [p["serial_number"] for p in manufacturer_serials]
        
        total_verifications = 0
        if serial_numbers:
            total_verifications = db.verification_logs.count_documents({
                "serial_number": {"$in": serial_numbers}
            })
        
        return create_cors_response({
            'success': True,
            'total_products': total_products,
            'blockchain_products': blockchain_products,
            'pending_products': pending_products,
            'total_verifications': total_verifications
        }, 200)
        
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@app.route('/manufacturer/products', methods=['GET', 'OPTIONS'])
@token_required_with_roles(['manufacturer'])
def get_manufacturer_products(current_user_id, current_user_role):
    """Get products for manufacturer with optional filtering"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        # Debug logging
        print(f"Fetching products for user: {current_user_id}")
        
        # Validate user ID and get user
        try:
            user_id = ObjectId(current_user_id) if isinstance(current_user_id, str) else current_user_id
            user = get_user_by_id(user_id)
        except Exception as e:
            print(f"User ID validation error: {e}")
            return create_cors_response({'error': 'Invalid user ID'}, 400)

        if not user:
            print("User not found")
            return create_cors_response({'error': 'User not found'}, 404)

        manufacturer_wallet = user.get('primary_wallet')
        if not manufacturer_wallet:
            print("No wallet address found for user")
            return create_cors_response({'error': 'No wallet address found'}, 400)
            
        print(f"Manufacturer wallet: {manufacturer_wallet}")

        # Get database connection
        db = get_db_connection()
        if db is None:
            print("Database connection failed")
            return create_cors_response({'error': 'Database connection failed'}, 500)

        # FIXED: Use correct collection name - change "products" to "produts" if that's your actual collection name
        # If your collection is actually called "produts", change the line below:
        collection = db.products  # Change to db.produts if that's your collection name
        
        # Build query with optional filter
        filter_type = request.args.get('filter', 'all')
        query = {"manufacturer_wallet": manufacturer_wallet}
        
        print(f"Base query: {query}")
        
        filter_mapping = {
            'blockchain_confirmed': 'blockchain_confirmed',
            'blockchain_pending': 'blockchain_pending',
            'blockchain_failed': 'blockchain_failed',
        }
        
        if filter_type != 'all' and filter_type in filter_mapping:
            query["registration_type"] = filter_mapping[filter_type]
            
        print(f"Final query: {query}")

        # Debug: Check if collection exists and has documents
        try:
            total_count = collection.count_documents({})
            user_count = collection.count_documents(query)
            print(f"Total documents in collection: {total_count}")
            print(f"Documents matching query: {user_count}")
        except Exception as e:
            print(f"Collection query debug error: {e}")

        # Fetch products with error handling
        try:
            products = list(collection.find(query).sort("created_at", -1))
            print(f"Found {len(products)} products")
        except Exception as e:
            print(f"Database query error: {e}")
            return create_cors_response({'error': f'Database query failed: {str(e)}'}, 500)

        # Format products for frontend
        formatted_products = []
        for product in products:
            try:
                formatted_product = {
                    'id': str(product.get('_id', '')),
                    'serial_number': product.get('serial_number', ''),
                    'name': product.get('name', f"{product.get('brand', '')} {product.get('model', '')}".strip()),
                    'brand': product.get('brand', ''),
                    'model': product.get('model', ''),
                    'device_type': product.get('device_type', ''),
                    'category': product.get('category', product.get('device_type', '')),
                    'registration_type': product.get('registration_type', ''),
                    'transaction_hash': product.get('transaction_hash', ''),
                    'price': product.get('price', 0),
                    'created_at': str(product.get('created_at', '')) if product.get('created_at') else ''
                }
                formatted_products.append(formatted_product)
            except Exception as e:
                print(f"Error formatting product {product.get('_id')}: {e}")
                # Skip this product and continue

        response_data = {
            'success': True,
            'products': formatted_products,
            'total_count': len(formatted_products)
        }
        
        print(f"Returning {len(formatted_products)} formatted products")

        # FIXED: Correct way to handle CORS response with additional headers
        return create_cors_response(response_data, 200)
        
    except Exception as e:
        print(f"Error in get_manufacturer_products: {e}")
        import traceback
        traceback.print_exc()
        return create_cors_response({'error': 'Internal server error'}, 500)
    
@app.route('/products/<product_id>/blockchain-confirm', methods=['PUT'])
@token_required_with_roles(['manufacturer'])
def confirm_blockchain_registration(current_user_id, current_user_role, product_id):
    """Confirm blockchain registration for a product"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        data = request.get_json()
        
        # Update product with blockchain confirmation
        db = get_db_connection()
        result = db.products.update_one(
            {"_id": ObjectId(product_id), "manufacturer_id": current_user_id},
            {
                "$set": {
                    "registration_type": "blockchain_confirmed",
                    "transaction_hash": data.get('transactionHash'),
                    "block_number": data.get('blockNumber'),
                    "gas_used": data.get('gasUsed'),
                    "gas_price": data.get('gasPrice'),
                    "blockchain_verified": True,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )
        
        if result.matched_count == 0:
            return create_cors_response({'error': 'Product not found or unauthorized'}, 404)
        
        return create_cors_response({
            'success': True, 
            'message': 'Blockchain registration confirmed'
        }, 200)
        
    except Exception as e:
        print(f"Blockchain confirmation error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@app.route('/products/<product_id>/blockchain-failed', methods=['PUT'])
@token_required_with_roles(['manufacturer'])
def mark_blockchain_failed(current_user_id, current_user_role, product_id):
    """Mark blockchain registration as failed"""
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({'error': 'User not found'}, 404)
        
        data = request.get_json()
        
        # Update product status to failed
        db = get_db_connection()
        result = db.products.update_one(
            {"_id": ObjectId(product_id), "manufacturer_wallet": user.get('primary_wallet')},
            {
                "$set": {
                    "registration_type": "blockchain_failed",
                    "error": data.get('error'),
                    "updated_at": get_current_utc()
                }
            }
        )
        
        if result.matched_count == 0:
            return create_cors_response({
                'error': 'Product not found or not owned by this manufacturer'
            }, 404)
        
        return create_cors_response({
            'success': True,
            'message': 'Blockchain registration marked as failed'
        }, 200)
        
    except Exception as e:
        print(f"Mark blockchain failed error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@app.route('/products/transfer-ownership', methods=['PUT'])
@token_required_with_roles(['manufacturer', 'customer'])
def transfer_ownership(current_user_id, current_user_role):
    """Transfer product ownership"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['serialNumber', 'newOwnerAddress', 'transferReason']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({'error': 'User not found'}, 404)
        
        db = get_db_connection()
        
        # Find the product
        product = db.products.find_one({"serial_number": data['serialNumber']})
        if not product:
            return create_cors_response({'error': 'Product not found'}, 404)
        
        # Verify ownership authorization
        current_owner_wallet = user.get('primary_wallet')
        ownership_history = product.get("ownership_history", [])
        
        # Determine current owner
        if ownership_history:
            current_owner = ownership_history[-1]["owner_address"]
        else:
            current_owner = product.get("manufacturer_wallet")
        
        if current_owner != current_owner_wallet:
            return create_cors_response({
                'error': 'You are not the current owner of this product'
            }, 403)
        
        # Create new ownership entry
        new_ownership_entry = {
            "owner_address": data['newOwnerAddress'],
            "owner_type": "customer",
            "owner_name": data.get('newOwnerName', 'Unknown'),
            "previous_owner": current_owner_wallet,
            "transfer_date": datetime.now(timezone.utc),
            "transfer_type": data['transferReason'],
            "transaction_hash": data.get('transactionHash'),
            "sale_price": float(data.get('salePrice', 0)),
            "notes": data.get('notes', '')
        }
        
        # Update product with new ownership
        updated_history = ownership_history + [new_ownership_entry]
        
        db.products.update_one(
            {"serial_number": data['serialNumber']},
            {
                "$set": {
                    "ownership_history": updated_history,
                    "current_owner": data['newOwnerAddress'],
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )
        
        # Create separate transfer record for backwards compatibility
        transfer_record = {
            "serial_number": data['serialNumber'],
            "previous_owner": current_owner_wallet,
            "new_owner": data['newOwnerAddress'],
            "transfer_reason": data['transferReason'],
            "transaction_hash": data.get('transactionHash'),
            "transfer_date": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc)
        }
        
        db.ownership_transfers.insert_one(transfer_record)
        
        return create_cors_response({
            'success': True,
            'message': 'Ownership transferred successfully'
        }, 200)
        
    except Exception as e:
        print(f"Transfer ownership error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

# ===============================
# PROFILE MANAGEMENT ROUTES
# ===============================

def update_user_profile_field(current_user_id, update_data, success_message):
    """Helper function to update user profile fields"""
    try:
        db = get_db_connection()
        result = db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$set": {**update_data, "updated_at": datetime.now(timezone.utc)}}
        )
        
        if result.matched_count == 0:
            return None, "User not found"
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return {
            "status": "success",
            "message": success_message,
            "user": profile_data
        }, None
        
    except Exception as e:
        print(f"Profile update error: {e}")
        return None, "Internal server error"

@app.route('/manufacturer/profile/add-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def add_email(current_user_id, current_user_role):
    """Add email to manufacturer profile"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return create_cors_response({"error": "Email address is required"}, 400)
            
        # Validate email format
        if not is_valid_email(email):
            return create_cors_response({"error": "Invalid email format"}, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_emails = user.get('emails', [])
        if email in current_emails:
            return create_cors_response({"error": "Email already exists"}, 400)
            
        # Check if email is used by another user
        if email_exists_globally(email, current_user_id):
            return create_cors_response({
                "error": "Email is already registered to another account"
            }, 400)
        
        # Update user profile
        updated_emails = current_emails + [email]
        result, error = update_user_profile_field(
            current_user_id,
            {"emails": updated_emails},
            "Email added successfully"
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Add email error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@app.route('/manufacturer/profile/remove-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def remove_email(current_user_id, current_user_role):
    """Remove email from manufacturer profile"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return create_cors_response({"error": "Email address is required"}, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_emails = user.get('emails', [])
        primary_email = get_primary_email(user)
        
        # Check if trying to remove primary email
        if email == primary_email:
            return create_cors_response({"error": "Cannot remove primary email"}, 400)
            
        # Check if email exists
        if email not in current_emails:
            return create_cors_response({"error": "Email not found"}, 404)
            
        # Remove email from list
        updated_emails = [e for e in current_emails if e != email]
        
        result, error = update_user_profile_field(
            current_user_id,
            {"emails": updated_emails},
            "Email removed successfully"
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Remove email error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@app.route('/manufacturer/profile/set-primary-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def set_primary_email(current_user_id, current_user_role):
    """Set primary email for manufacturer"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return create_cors_response({"error": "Email address is required"}, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_emails = user.get('emails', [])
        
        # Check if email exists
        if email not in current_emails:
            return create_cors_response({"error": "Email not found"}, 404)
        
        result, error = update_user_profile_field(
            current_user_id,
            {"primary_email": email},
            "Primary email updated successfully"
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Set primary email error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@app.route('/manufacturer/profile/add-wallet', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def add_wallet(current_user_id, current_user_role):
    """Add wallet to manufacturer profile"""
    try:
        data = request.get_json()
        wallet_address = data.get('wallet_address', '').strip()
        
        if not wallet_address:
            return create_cors_response({"error": "Wallet address is required"}, 400)
            
        # Validate wallet address format
        if not is_valid_wallet_address(wallet_address):
            return create_cors_response({"error": "Invalid wallet address format"}, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_wallets = user.get('wallet_addresses', [])
        
        # Check if wallet already exists
        if wallet_address in current_wallets:
            return create_cors_response({"error": "Wallet already exists"}, 400)
            
        # Check if wallet is used by another user
        if wallet_exists_globally(wallet_address, current_user_id):
            return create_cors_response({
                "error": "Wallet is already registered to another account"
            }, 400)
        
        # Add wallet to user's wallet list
        updated_wallets = current_wallets + [wallet_address]
        update_data = {"wallet_addresses": updated_wallets}
        
        # Set as primary wallet if it's the first one
        if not user.get('primary_wallet'):
            update_data["primary_wallet"] = wallet_address
        
        result, error = update_user_profile_field(
            current_user_id,
            update_data,
            "Wallet added successfully. Verification required before use."
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Add wallet error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@app.route('/manufacturer/profile/set-primary-wallet', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def set_primary_wallet(current_user_id, current_user_role):
    """Set primary wallet for manufacturer"""
    try:
        data = request.get_json()
        wallet_address = data.get('wallet_address', '').strip()
        
        if not wallet_address:
            return create_cors_response({"error": "Wallet address is required"}, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_wallets = user.get('wallet_addresses', [])
        verified_wallets = user.get('verified_wallets', [])
        
        # Check if wallet exists
        if wallet_address not in current_wallets:
            return create_cors_response({"error": "Wallet not found"}, 404)
            
        # Check if wallet is verified
        if wallet_address not in verified_wallets:
            return create_cors_response({
                "error": "Wallet must be verified before setting as primary"
            }, 400)
        
        result, error = update_user_profile_field(
            current_user_id,
            {"primary_wallet": wallet_address},
            "Primary wallet updated successfully"
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Set primary wallet error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@app.route('/manufacturer/profile/update-company-name', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def update_company_name(current_user_id, current_user_role):
    """Update company name for manufacturer"""
    try:
        data = request.get_json()
        company_name = data.get('company_name', '').strip()
        
        if not company_name:
            return create_cors_response({"error": "Company name is required"}, 400)
            
        if len(company_name) < 2:
            return create_cors_response({
                "error": "Company name must be at least 2 characters"
            }, 400)
            
        if len(company_name) > 100:
            return create_cors_response({
                "error": "Company name must be less than 100 characters"
            }, 400)
        
        user = get_user_by_id(current_user_id)
        if not user:
            return create_cors_response({"error": "User not found"}, 404)
            
        current_company = get_current_company_name(user)
        
        # Check if new name is different from current
        if company_name == current_company:
            return create_cors_response({
                "error": "New company name must be different from current name"
            }, 400)
        
        current_company_names = user.get('company_names', [])
        
        # Add new company name if not already in history
        updated_company_names = current_company_names
        if company_name not in current_company_names:
            updated_company_names = current_company_names + [company_name]
        
        result, error = update_user_profile_field(
            current_user_id,
            {
                "company_names": updated_company_names,
                "current_company_name": company_name
            },
            "Company name updated successfully"
        )
        
        if error:
            return create_cors_response({"error": error}, 500)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Update company name error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

# ===============================
# CONFIGURATION AND UTILITY ROUTES
# ===============================

@app.route('/blockchain-config', methods=['GET'])
def get_blockchain_config():
    """Return blockchain configuration for frontend"""
    try:
        config = {
            "chainId": os.getenv('CHAINID'),      
            "rpcUrl": os.getenv('BLOCKCHAIN_RPC_URL'),
            "contractAddress": os.getenv('CONTRACT_ADDRESS'),
            "walletAddress": os.getenv('WALLET_ADDRESS')
        }
        
        return create_cors_response(config, 200)
        
    except Exception as e:
        print(f"Blockchain config error: {e}")
        return create_cors_response({
            "error": "Could not load blockchain configuration"
        }, 500)

# ===============================
# FRONTEND ROUTES
# ===============================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard with safe environment variable handling"""
    # Provide safe defaults
    chain_id = int(os.getenv('CHAIN_ID', '11155111'))
    contract_address = os.getenv('CONTRACT_ADDRESS', '')
    account_address = os.getenv('ACCOUNT_ADDRESS', '')
    rpc_url = os.getenv('RPC_URL', '')
    
    # Handle contract ABI safely
    contract_abi = '[]'  # Default empty array
    contract_abi_path = os.getenv('CONTRACT_ABI_PATH', '')
    
    if contract_abi_path and os.path.exists(contract_abi_path):
        try:
            with open(contract_abi_path, 'r') as f:
                abi_content = f.read()
            # Validate JSON
            import json
            json.loads(abi_content)  # Test validity
            contract_abi = abi_content
        except (json.JSONDecodeError, IOError, TypeError) as e:
            print(f"Error reading ABI file {contract_abi_path}: {e}")
            contract_abi = '[]'  # Fallback
    else:
        print(f"ABI file not found at path: {contract_abi_path}")
    
    return render_template('dashboard.html',
                         chain_id=chain_id,
                         contract_address=contract_address,
                         wallet_address=account_address,
                         contract_abi=contract_abi,
                         rpc_url=rpc_url)
    
@app.route('/verify')
def verify_page():
    return render_template('verify.html')

@app.route('/edit-profile')
def edit_profile():
    return render_template('edit-profile.html')

# ===============================
# APPLICATION STARTUP
# ===============================

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    )