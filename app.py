# app.py - Main Flask Application
from bson import ObjectId
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from web3 import Web3
import hashlib
import re
# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
CORS(app)

# Initialize Web3 (you'll need this for blockchain operations)
try:
    w3 = Web3(Web3.HTTPProvider(os.getenv('BLOCKCHAIN_RPC_URL')))
except:
    w3 = None
    print("Warning: Web3 not initialized")

# Import all helper functions
from helper_functions import (
    # Database functions
    get_user_by_email, get_user_by_id, create_user, update_user_verification_status, get_db_connection,
    get_product_by_serial, create_product, get_all_products, get_products_by_manufacturer,
    get_pending_manufacturers, create_api_key, get_api_keys_by_user, validate_api_key, update_user,
    get_primary_email, get_primary_wallet, is_valid_email, is_valid_wallet_address, email_exists_globally,
    wallet_exists_globally, get_current_company_name, get_verified_wallets, generate_verification_token,
    send_email_verification, initiate_wallet_verification,  format_user_profile,  validate_product_data,
    validate_ownership_transfer, get_ownership_history_by_serial, create_ownership_transfer,
    
    # Blockchain functions
    verify_on_blockchain, register_product_blockchain, verify_manufacturer_on_blockchain,
    check_manufacturer_authorization, get_blockchain_product_details,
    
    # Utility functions
    hash_password, verify_password, format_product_response, format_user_response,
    get_current_utc,
    
    # Validation functions
    validate_user_registration, validate_product_data, ValidationError, 
    AuthenticationError, BlockchainError,
    
    # New verification classes
    ElectronicsAuthenticator, DatabaseManager
)

# Serve static files
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# JWT Token validation functions
def validate_token(token, secret_key):
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
    except Exception as e:
        return None, None, {'message': 'Token validation failed'}, 401

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        user_id, user_role, error, status = validate_token(token, app.config['SECRET_KEY'])
        if error:
            return jsonify(error), status
        return f(user_id, user_role, *args, **kwargs)
    return decorated

def token_required_with_roles(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            user_id, user_role, error, status = validate_token(token, app.config['SECRET_KEY'])
            if error:
                return jsonify(error), status
            if allowed_roles and user_role not in allowed_roles:
                return jsonify({'message': f'Access denied: requires one of {allowed_roles}'}), 403
            return f(user_id, user_role, *args, **kwargs)
        return decorated
    return decorator

def api_key_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        
        if not api_key:
            return jsonify({'message': 'API key is required'}), 401
            
        key_data = validate_api_key(api_key)
        if not key_data:
            return jsonify({'message': 'Invalid API key'}), 401
            
        return f(*args, **kwargs)
    return decorator

# ===============================
# PUBLIC VERIFICATION ROUTES (for verify.html)
# ===============================

@app.route('/verify/<serial_number>', methods=['GET'])
def verify_product_public(serial_number):
    """Public verification endpoint for verify.html page"""
    try:
        # Initialize authenticator
        db = get_db_connection()
        authenticator = ElectronicsAuthenticator(db, w3)
        
        # Get user info for logging
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Verify the device
        result = authenticator.verify_single_device(serial_number, user_ip, user_agent)
        
        if result["authentic"]:
            return jsonify({
                "authentic": True,
                "brand": result.get("brand"),
                "model": result.get("model"),
                "deviceType": result.get("deviceType"),
                "storage": result.get("storage"),
                "color": result.get("color"),
                "manufacturerName": result.get("manufacturerName"),
                "source": result.get("source"),
                "confidence": result.get("confidence"),
                "message": "Product verified successfully"
            }), 200
        else:
            return jsonify({
                "authentic": False,
                "message": result.get("message", "Product not found or not authentic"),
                "source": result.get("source", "unknown"),
                "confidence": result.get("confidence", 0)
            }), 200
            
    except Exception as e:
        print(f"Public verification error: {e}")
        return jsonify({
            "authentic": False,
            "message": "Verification service temporarily unavailable"
        }), 500

@app.route('/verify-batch', methods=['POST'])
def verify_batch_public():
    """Public batch verification endpoint"""
    try:
        data = request.get_json()
        serial_numbers = data.get('serialNumbers', [])
        
        if not serial_numbers or len(serial_numbers) > 10:
            return jsonify({
                "error": "Please provide 1-10 serial numbers"
            }), 400
        
        db = get_db_connection()
        authenticator = ElectronicsAuthenticator(db, w3)
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Verify batch
        results = authenticator.verify_batch_devices(serial_numbers, user_ip)
        
        return jsonify({
            "status": "success",
            "results": results,
            "total_verified": len([r for r in results if r["authentic"]]),
            "total_checked": len(results)
        }), 200
        
    except Exception as e:
        print(f"Batch verification error: {e}")
        return jsonify({"error": "Batch verification failed"}), 500

@app.route('/sample-data', methods=['GET'])
def get_sample_data():
    """Get sample serial numbers for testing"""
    try:
        db = get_db_connection()
        
        # Get authentic devices from blockchain
        blockchain_devices = list(db.products.electronics.find(
            {"isOnBlockchain": True, "isAuthentic": True}
        ).limit(5))
        
        # Get authentic devices from database
        database_devices = list(db.electronics.find(
            {"isOnBlockchain": False, "isAuthentic": True}
        ).limit(5))
        
        # Some fake serials for testing
        fake_serials = ["FAKE001", "INVALID123", "COUNTERFEIT", "NOTREAL999", "BOGUS456"]
        
        sample_data = {
            "authentic": {
                "blockchain": [device["serialNumber"] for device in blockchain_devices],
                "database": [device["serialNumber"] for device in database_devices]
            },
            "counterfeit": fake_serials
        }
        
        return jsonify(sample_data), 200
        
    except Exception as e:
        print(f"Sample data error: {e}")
        return jsonify({"error": "Could not load sample data"}), 500

@app.route('/stats', methods=['GET'])
def get_verification_stats():
    """Get system verification statistics"""
    try:
        db = get_db_connection()
        db_manager = DatabaseManager(db)
        
        stats = db_manager.get_system_stats()
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"Stats error: {e}")
        return jsonify({"error": "Could not load stats"}), 500

@app.route('/ownership-history/<serial_number>', methods=['GET'])
def get_ownership_history(serial_number):
    """Get ownership history for a verified product"""
    try:
        db = get_db_connection()
        authenticator = ElectronicsAuthenticator(db, w3)
        
        history = authenticator.get_ownership_history(serial_number)
        
        if history:
            return jsonify({
                "status": "success",
                "serial_number": serial_number,
                "history": history
            }), 200
        else:
            return jsonify({
                "status": "not_found",
                "message": "No ownership history found for this device"
            }), 404
            
    except Exception as e:
        print(f"Ownership history error: {e}")
        return jsonify({"error": "Could not load ownership history"}), 500

@app.route('/device-details/<serial_number>', methods=['GET'])
def get_device_details(serial_number):
    """Get detailed device information"""
    try:
        db = get_db_connection()
        db_manager = DatabaseManager(db)
        
        details = db_manager.get_device_details(serial_number)
        
        if details:
            return jsonify({
                "status": "success",
                **details
            }), 200
        else:
            return jsonify({
                "status": "not_found",
                "error": "Device details not found"
            }), 404
            
    except Exception as e:
        print(f"Device details error: {e}")
        return jsonify({"error": "Could not load device details"}), 500

@app.route('/seed-data', methods=['GET'])
def seed_sample_data():
    """Seed database with sample verification data"""
    try:
        db = get_db_connection()
        db_manager = DatabaseManager(db)
        
        result = db_manager.seed_sample_data()
        
        return jsonify({
            "status": "success",
            "message": result["message"],
            "details": result
        }), 200
        
    except Exception as e:
        print(f"Seed data error: {e}")
        return jsonify({"error": "Could not seed sample data"}), 500

# ===============================
# AUTHENTICATION ROUTES
# ===============================

@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate input data
        validate_user_registration(data)
        
        # Check if user already exists
        existing_user = get_user_by_email(data["email"])
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 400
        
        # Create user data
        user_data = {
            "emails": [data["email"]],  
            "primary_email": data["email"],  
            "password_hash": hash_password(data["password"]),
            "role": data["role"],
            "created_at": get_current_utc(),
        }

        # For manufacturers:
        if data["role"] == "manufacturer":
            user_data["wallet_addresses"] = [data["wallet_address"]]  
            user_data["primary_wallet"] = data["wallet_address"]  
            user_data["company_names"] = [data.get("company_name", "")]  
            user_data["current_company_name"] = data.get("company_name", "") 
            user_data["verification_status"] = "pending"
            user_data["verified_wallets"] = []  
        
        # Create user
        user_id = create_user(user_data)
        
        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id
        }), 201
        
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        
        # Get user
        user = get_user_by_email(email)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
            
        # Check password
        if not verify_password(user["password_hash"], password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Create JWT token with fallback for old user format
        user_email = user.get("primary_email") or user.get("email")
        
        token_payload = {
            'sub': str(user["_id"]),
            'role': user["role"],
            'email': user_email,
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            "status": "success",
            "token": token,
            "user": format_user_response(user)
        }), 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ===============================
# MANUFACTURER ROUTES
# ===============================

@app.route('/manufacturer/profile', methods=['GET'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def get_profile(current_user_id, current_user_role):
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Format response with enhanced data
        profile_data = {
            "name": user.get('name'),
            "role": user.get('role'),
            "emails": user.get('emails', []),
            "primary_email": get_primary_email(user),
            "created_at": user.get('created_at')
        }
        
        if user.get('role') == 'manufacturer':
            profile_data.update({
                "wallet_addresses": user.get('wallet_addresses', []),
                "primary_wallet": get_primary_wallet(user),
                "verified_wallets": get_verified_wallets(user),
                "company_names": user.get('company_names', []),
                "current_company_name": get_current_company_name(user)
            })
            
        return jsonify({
            "status": "success",
            "user": profile_data
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/manufacturer/register-product', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def register_manufacturer_product(current_user_id, current_user_role):
    try:
        data = request.get_json()
        print(f"Received registration data: {data}")  # Debug log
        
        # Validate product data - handle both field name formats
        serial_number = data.get('serialNumber') or data.get('serial_number')
        brand = data.get('brand')
        model = data.get('model')
        device_type = data.get('deviceType') or data.get('device_type')
        
        if not all([serial_number, brand, model, device_type]):
            return jsonify({"error": "Missing required fields: serialNumber, brand, model, deviceType"}), 400
        
        # Get manufacturer info
        manufacturer = get_user_by_id(current_user_id)
        if not manufacturer:
            return jsonify({"error": "Manufacturer not found"}), 404
        
        # Check if manufacturer account is verified
        if manufacturer.get("verification_status") != "verified":
            return jsonify({"error": "Your account is not verified by admin yet"}), 403
        
        # Get primary wallet
        primary_wallet = manufacturer.get('primary_wallet')
        if not primary_wallet:
            return jsonify({"error": "No wallet address found. Please add a wallet first."}), 400
        
        # Get current company name
        current_company_name = manufacturer.get('current_company_name')
        if not current_company_name:
            return jsonify({"error": "Company name not set"}), 400
        
        # Check if product serial already exists
        existing_product = get_product_by_serial(serial_number)
        if existing_product:
            return jsonify({"error": "Product with this serial number already exists"}), 400
        
        # Prepare product data with consistent field names
        product_data = {
            "_id": ObjectId(),
            "serial_number": serial_number,
            "brand": brand,
            "model": model,
            "device_type": device_type,
            "storage_data": data.get('storageData', ''),
            "color": data.get('color', ''),
            "batch_number": data.get('batchNumber', f"BATCH-{int(datetime.utcnow().timestamp())}"),
            "name": f"{brand} {model}",
            "category": device_type,
            "description": f"{brand} {model} - {data.get('storageData', '')} {data.get('color', '')}",
            "manufacturer_wallet": data.get('manufacturerWallet', primary_wallet),
            "specification_hash": data.get('specificationHash', ''),
            "registration_type": data.get('registrationType', 'blockchain_pending'),
            "manufacturer_id": current_user_id,
            "manufacturer_name": current_company_name,
            "wallet_address": primary_wallet,
            "blockchain_verified": data.get('registrationType') == 'blockchain_confirmed',
            "registered_at": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        # Add blockchain data if provided
        if data.get('transactionHash'):
            product_data.update({
                "transaction_hash": data['transactionHash'],
                "block_number": data.get('blockNumber'),
                "gas_used": data.get('gasUsed'),
                "gas_price": data.get('gasPrice')
            })
        
        # Save to database
        try:
            db = get_db_connection()
            result = db.products.insert_one(product_data)
            product_id = str(result.inserted_id)
            
            print(f"Product saved with ID: {product_id}")  # Debug log
            db.users.update_one({"_id": product_id}, {"$set": {"last_product_update": get_current_utc()}})
            
            return jsonify({
                "status": "success",
                "message": "Product registered successfully",
                "product_id": product_id,
                "serial_number": serial_number,
                "product": {
                    "id": product_id,
                    "serial_number": serial_number,
                    "brand": brand,
                    "model": model,
                    "name": f"{brand} {model}",
                    "registration_type": product_data["registration_type"]
                }
            }), 201
            
        except Exception as db_error:
            print(f"Database error: {db_error}")
            return jsonify({"error": "Failed to save product to database"}), 500
        
    except Exception as e:
        print(f"Product registration error: {e}")
        import traceback
        traceback.print_exc()  # Full error trace
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# Add these new routes for manufacturer dashboard

@app.route('/manufacturer/dashboard-stats')
@token_required_with_roles(['manufacturer'])
def get_manufacturer_dashboard_stats(current_user_id, current_user_role):
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return jsonify({'error': 'Unauthorized'}), 403
        
        manufacturer_wallet = user.get('primary_wallet')
        db = get_db_connection()
        # Count products by status
        total_products = db.products.count_documents({
            "manufacturer_wallet": manufacturer_wallet
        })

        blockchain_products = db.products.count_documents({
            "manufacturer_wallet": manufacturer_wallet,
            "registration_type": "blockchain_confirmed"
        })

        pending_products = db.products.count_documents({
            "manufacturer_wallet": manufacturer_wallet,
            "registration_type": "blockchain_pending"
        })
        
        # Count verifications for this manufacturer's products
        manufacturer_serials = list(db.products.find(
            {"manufacturer_wallet": manufacturer_wallet}, 
            {"serial_number": 1}
        ))
        serial_numbers = [p["serial_number"] for p in manufacturer_serials]

        total_verifications = db.verification_logs.count_documents({
            "serial_number": {"$in": serial_numbers}
        }) if serial_numbers else 0
        
        return jsonify({
            'success': True,
            'total_products': total_products,
            'blockchain_products': blockchain_products,
            'pending_products': pending_products,
            'total_verifications': total_verifications
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/manufacturer/products')
@token_required_with_roles(['manufacturer'])
def get_manufacturer_products(current_user_id, current_user_role):
    try:
        # Safer ObjectId conversion
        try:
            if isinstance(current_user_id, str):
                user_id = ObjectId(current_user_id)
            else:
                user_id = current_user_id
            user = get_user_by_id(user_id)
            print(f"User retrieved: {user}")
        except Exception as oid_error:
            print(f"Invalid user ID format: {current_user_id}, Error: {oid_error}")
            return jsonify({'error': 'Invalid user ID'}), 400

        # Safety checks after getting the user
        if not user:
            print(f"No user found for ID: {current_user_id}")
            return jsonify({'error': 'User not found'}), 404

        manufacturer_wallet = user.get('primary_wallet')
        if not manufacturer_wallet:
            print(f"No wallet for user: {user}")
            return jsonify({'error': 'No wallet address found for user'}), 400

        # Database connection check
        try:
            db = get_db_connection()
            if db is None:  # Changed from 'if not db' to 'if db is None'
                print("Database connection failed")
                return jsonify({'error': 'Database connection failed'}), 500
            print("Database connected successfully")
        except Exception as db_error:
            print(f"Database connection error: {db_error}")
            return jsonify({'error': 'Database unavailable'}), 500

        # Build query based on filter
        filter_type = request.args.get('filter', 'all')
        query = {"manufacturer_wallet": manufacturer_wallet}
        if filter_type != 'all':
            filter_mapping = {
                'blockchain_confirmed': 'blockchain_confirmed',
                'blockchain_pending': 'blockchain_pending', 
                'blockchain_failed': 'blockchain_failed',
            }
            if filter_type in filter_mapping:
                query["registration_type"] = filter_mapping[filter_type]
        print(f"Query constructed: {query}")

        # Wrap database query in try-except
        try:
            products = list(db.products.find(query).sort("created_at", -1))
            print(f"Products fetched: {len(products)}")
        except Exception as query_error:
            print(f"Database query failed: {query_error}")
            return jsonify({'error': 'Failed to retrieve products'}), 500

        # Convert ObjectId to string and handle missing fields
        for product in products:
            product['_id'] = str(product.get('_id', ''))
        
        # Format products for frontend
        formatted_products = []
        for product in products:
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
        
        response = jsonify({
            'success': True,
            'products': formatted_products
        })
        
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        print(f"Error in get_manufacturer_products: {str(e)}")
        return jsonify({'error': 'Internal server error occurred'}), 500


@app.route('/products/<product_id>/blockchain-confirm', methods=['PUT'])
@token_required_with_roles(['manufacturer'])
def confirm_blockchain_registration(current_user_id, current_user_role, product_id):
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return jsonify({'error': 'Unauthorized'}), 403
        
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
            return jsonify({'error': 'Product not found or unauthorized'}), 404
        
        return jsonify({'success': True, 'message': 'Blockchain registration confirmed'})
        
    except Exception as e:
        print(f"Blockchain confirmation error: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    
@app.route('/products/transfer-ownership', methods=['POST'])
@token_required_with_roles(['manufacturer'])
def transfer_ownership(current_user_id, current_user_role):
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['serialNumber', 'newOwnerAddress', 'transferReason']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Verify the product belongs to this manufacturer
        db = get_db_connection()
        product = db.products.find_one({
            "serial_number": data['serialNumber'],
            "manufacturer_wallet": user.get('primary_wallet')
        })
        
        if not product:
            return jsonify({'error': 'Product not found or not owned by you'}), 404
        
        # Create ownership transfer record
        transfer_record = {
            "serial_number": data['serialNumber'],
            "previous_owner": user.get('primary_wallet'),
            "new_owner": data['newOwnerAddress'],
            "transfer_reason": data['transferReason'],
            "sale_price": float(data.get('salePrice', 0)),
            "transaction_hash": data.get('transactionHash'),
            "block_number": data.get('blockNumber'),
            "transfer_date": datetime.utcnow(),
            "created_at": datetime.utcnow()
        }
        
        # Insert transfer record
        db.ownership_transfers.insert_one(transfer_record)
        
        # Update product's current owner
        db.products.update_one(
            {"serial_number": data['serialNumber']},
            {
                "$set": {
                    "current_owner": data['newOwnerAddress'],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'Ownership transferred successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/products/<product_id>/blockchain-failed', methods=['PUT'])
@token_required_with_roles(['manufacturer'])
def mark_blockchain_failed(current_user_id, product_id):
    try:
        user = get_user_by_id(current_user_id)
        
        data = request.get_json()
        
        # Update product status to failed
        db = get_db_connection()
        result = db.products.update_one(
            {"_id": ObjectId(product_id), "manufacturerWallet": user.get('primary_wallet')},
            {
            "$set": {
            "registrationType": "blockchain_failed",
            "error": data.get('error'),
            "updatedAt": get_current_utc()
            }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Product not found or not owned by this manufacturer'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Blockchain registration marked as failed'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# Add Email Route
@app.route('/manufacturer/profile/add-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def add_email(current_user_id, current_user_role):
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email address is required"}), 400
            
        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return jsonify({"error": "Invalid email format"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Check if email already exists
        current_emails = user.get('emails', [])
        if email in current_emails:
            return jsonify({"error": "Email already exists"}), 400
        db = get_db_connection()
        # Check if email is already used by another user
        existing_user = db.users.find_one({"emails": email})
        if existing_user and str(existing_user['_id']) != current_user_id:
            return jsonify({"error": "Email is already registered to another account"}), 400
        
        # Add email to user's email list
        updated_emails = current_emails + [email]
        
        # Update user in database
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {
                "$set": {
                    "emails": updated_emails,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # TODO: Send verification email here
        # send_verification_email(email, current_user_id)
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Email added successfully. Verification email sent.",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Add email error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Remove Email Route
@app.route('/manufacturer/profile/remove-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def remove_email(current_user_id, current_user_role):
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email address is required"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_emails = user.get('emails', [])
        primary_email = get_primary_email(user)
        
        # Check if trying to remove primary email
        if email == primary_email:
            return jsonify({"error": "Cannot remove primary email"}), 400
            
        # Check if email exists
        if email not in current_emails:
            return jsonify({"error": "Email not found"}), 404
            
        # Remove email from list
        updated_emails = [e for e in current_emails if e != email]
        
        # Update user in database
        db = get_db_connection()
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {
                "$set": {
                    "emails": updated_emails,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Email removed successfully",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Remove email error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Set Primary Email Route
@app.route('/manufacturer/profile/set-primary-email', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def set_primary_email(current_user_id, current_user_role):
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email address is required"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_emails = user.get('emails', [])
        
        # Check if email exists and is verified
        if email not in current_emails:
            return jsonify({"error": "Email not found"}), 404
            
        # TODO: Check if email is verified
        # For now, assuming all emails in the list are verified
        
        # Update primary email
        db = get_db_connection()
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {
                "$set": {
                    "primary_email": email,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Primary email updated successfully",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Set primary email error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Add Wallet Route
@app.route('/manufacturer/profile/add-wallet', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def add_wallet(current_user_id, current_user_role):
    try:
        data = request.get_json()
        wallet_address = data.get('wallet_address', '').strip()
        label = data.get('label', '').strip()
        
        if not wallet_address:
            return jsonify({"error": "Wallet address is required"}), 400
            
        # Validate wallet address format (basic Ethereum address validation)
        if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
            return jsonify({"error": "Invalid wallet address format"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_wallets = user.get('wallet_addresses', [])
        
        # Check if wallet already exists
        if wallet_address in current_wallets:
            return jsonify({"error": "Wallet already exists"}), 400
            
        # Check if wallet is already used by another user
        db = get_db_connection()
        existing_user = db.users.find_one({"wallet_addresses": wallet_address})
        if existing_user and str(existing_user['_id']) != current_user_id:
            return jsonify({"error": "Wallet is already registered to another account"}), 400
        
        # Add wallet to user's wallet list
        updated_wallets = current_wallets + [wallet_address]
        
        # Update user in database
        update_data = {
            "wallet_addresses": updated_wallets,
            "updated_at": datetime.utcnow()
        }
        
        # Set as primary wallet if it's the first one
        if not user.get('primary_wallet'):
            update_data["primary_wallet"] = wallet_address
        db = get_db_connection()
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$set": update_data}
        )
        
        # TODO: Initiate wallet verification process
        # verify_wallet_ownership(wallet_address, current_user_id)
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Wallet added successfully. Verification required before use.",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Add wallet error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Set Primary Wallet Route
@app.route('/manufacturer/profile/set-primary-wallet', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def set_primary_wallet(current_user_id, current_user_role):
    try:
        data = request.get_json()
        wallet_address = data.get('wallet_address', '').strip()
        
        if not wallet_address:
            return jsonify({"error": "Wallet address is required"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_wallets = user.get('wallet_addresses', [])
        verified_wallets = user.get('verified_wallets', [])
        
        # Check if wallet exists
        if wallet_address not in current_wallets:
            return jsonify({"error": "Wallet not found"}), 404
            
        # Check if wallet is verified
        if wallet_address not in verified_wallets:
            return jsonify({"error": "Wallet must be verified before setting as primary"}), 400
        
        # Update primary wallet
        db = get_db_connection()
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {
                "$set": {
                    "primary_wallet": wallet_address,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Primary wallet updated successfully",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Set primary wallet error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Update Company Name Route
@app.route('/manufacturer/profile/update-company-name', methods=['POST'])
@token_required_with_roles(allowed_roles=['manufacturer'])
def update_company_name(current_user_id, current_user_role):
    try:
        data = request.get_json()
        company_name = data.get('company_name', '').strip()
        
        if not company_name:
            return jsonify({"error": "Company name is required"}), 400
            
        if len(company_name) < 2:
            return jsonify({"error": "Company name must be at least 2 characters"}), 400
            
        if len(company_name) > 100:
            return jsonify({"error": "Company name must be less than 100 characters"}), 400
        
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_company = get_current_company_name(user)
        
        # Check if new name is different from current
        if company_name == current_company:
            return jsonify({"error": "New company name must be different from current name"}), 400
        
        current_company_names = user.get('company_names', [])
        
        # Add new company name if not already in history
        if company_name not in current_company_names:
            updated_company_names = current_company_names + [company_name]
        else:
            updated_company_names = current_company_names
        
        # Update user in database
        db = get_db_connection()
        db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {
                "$set": {
                    "company_names": updated_company_names,
                    "current_company_name": company_name,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return jsonify({
            "status": "success",
            "message": "Company name updated successfully",
            "user": profile_data
        }), 200
        
    except Exception as e:
        print(f"Update company name error: {e}")
        return jsonify({"error": "Internal server error"}), 500



# ===============================
# LOAD BACKEND CONFIGURATION
# ===============================
@app.route('/blockchain-config', methods=['GET'])
def get_blockchain_config():
    """Return blockchain configuration for frontend"""
    try:
        return jsonify({
            "chainId": os.getenv('CHAINID'),      
            "rpcUrl": os.getenv('BLOCKCHAIN_RPC_URL'),
            "contractAddress": os.getenv('CONTRACT_ADDRESS'),
            "walletAddress": os.getenv('WALLET_ADDRESS')
            
        }), 200
    except Exception as e:
        print(f"Blockchain config error: {e}")
        return jsonify({"error": "Could not load blockchain configuration"}), 500
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
    # Provide safe defaults
    chain_id = int(os.getenv('CHAIN_ID', '11155111'))
    contract_address = os.getenv('CONTRACT_ADDRESS', '')
    account_address = os.getenv('ACCOUNT_ADDRESS', '')
    rpc_url = os.getenv('RPC_URL', '')
    
    # Read contract ABI from file path
    contract_abi = '[]'  # Default empty array
    contract_abi_path = os.getenv('CONTRACT_ABI_PATH', '')
    
    if contract_abi_path and os.path.exists(contract_abi_path):
        try:
            with open(contract_abi_path, 'r') as f:
                abi_content = f.read()
            # Validate it's valid JSON
            import json
            json.loads(abi_content)  # Test if it's valid JSON
            contract_abi = abi_content
        except (json.JSONDecodeError, IOError, TypeError) as e:
            print(f"Error reading ABI file {contract_abi_path}: {e}")
            contract_abi = '[]'  # Fallback to empty array
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
# ERROR HANDLERS
# ===============================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(ValidationError)
def handle_validation_error(error):
    return jsonify({"error": str(error)}), 400

@app.errorhandler(AuthenticationError)
def handle_auth_error(error):
    return jsonify({"error": str(error)}), 401

@app.errorhandler(BlockchainError)
def handle_blockchain_error(error):
    return jsonify({"error": str(error)}), 500

# ===============================
# HEALTH CHECK
# ===============================

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": get_current_utc(),
        "version": "1.0.0"
    }), 200

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    )