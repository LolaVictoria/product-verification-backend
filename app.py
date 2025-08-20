# app.py - Main Flask Application
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

# Import all helper functions
from helper_functions import (
    # Database functions
    get_user_by_email, get_user_by_id, create_user, update_user_verification_status,
    get_product_by_serial, create_product, get_all_products, get_products_by_manufacturer,
    get_pending_manufacturers, create_api_key, get_api_keys_by_user, validate_api_key,
    
    # Blockchain functions
    verify_on_blockchain, register_product_blockchain, verify_manufacturer_on_blockchain,
    check_manufacturer_authorization, get_blockchain_product_details,
    
    # Utility functions
    hash_password, verify_password, format_product_response, format_user_response,
    get_current_utc,
    
    # Validation functions
    validate_user_registration, validate_product_data, ValidationError, 
    AuthenticationError, BlockchainError
)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-default-secret-key')
CORS(app)

# JWT Token decorator
def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                return jsonify({'message': 'Token is missing'}), 401
                
            try:
                token = token.split(' ')[1]  # Remove 'Bearer '
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user_id = data['sub']
                current_user_role = data['role']
                
                if allowed_roles and current_user_role not in allowed_roles:
                    return jsonify({'message': 'Access denied'}), 403
                    
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Token is invalid'}), 401
                
            return f(current_user_id, current_user_role, *args, **kwargs)
        return decorated
    return decorator

# API Key decorator for public endpoints
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        
        if not api_key:
            return jsonify({'message': 'API key is required'}), 401
            
        key_data = validate_api_key(api_key)
        if not key_data:
            return jsonify({'message': 'Invalid API key'}), 401
            
        return f(*args, **kwargs)
    return decorated

# Authentication Routes
@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate input data
        validate_user_registration(data)
        
        # Create user data
        user_data = {
            "email": data["email"],
            "password_hash": hash_password(data["password"]),
            "role": data["role"]
        }
        
        # Add wallet address for manufacturers
        if data["role"] == "manufacturer":
            user_data["wallet_address"] = data["wallet_address"]
            user_data["verification_status"] = "pending"
        
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
        if not user or not verify_password(user["password_hash"], password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Create JWT token
        token_payload = {
            'sub': str(user["_id"]),
            'role': user["role"],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            "status": "success",
            "token": token,
            "user": format_user_response(user)
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth/profile', methods=['GET'])
@token_required()
def get_profile(current_user_id, current_user_role):
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "status": "success",
            "user": format_user_response(user)
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# Admin Routes
@app.route('/admin/pending-manufacturers', methods=['GET'])
@token_required(allowed_roles=['admin'])
def get_pending_manufacturers_route(current_user_id, current_user_role):
    try:
        manufacturers = get_pending_manufacturers()
        manufacturers_list = [format_user_response(m) for m in manufacturers]
        
        return jsonify({
            "status": "success",
            "manufacturers": manufacturers_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/verify-manufacturer/<manufacturer_id>', methods=['POST'])
@token_required(allowed_roles=['admin'])
def verify_manufacturer_route(current_user_id, current_user_role, manufacturer_id):
    try:
        action = request.json.get('action')  # 'approve' or 'reject'
        
        if action not in ['approve', 'reject']:
            return jsonify({"error": "Invalid action"}), 400
        
        # Update manufacturer status
        status = "approved" if action == "approve" else "rejected"
        success = update_user_verification_status(manufacturer_id, status)
        
        if not success:
            return jsonify({"error": "Manufacturer not found"}), 404
        
        # If approved, authorize manufacturer on blockchain
        if action == "approve":
            manufacturer = get_user_by_id(manufacturer_id)
            if manufacturer and manufacturer.get("wallet_address"):
                blockchain_result = verify_manufacturer_on_blockchain(manufacturer["wallet_address"])
                if not blockchain_result:
                    return jsonify({"warning": "Manufacturer approved in database but blockchain authorization failed"}), 200
        
        return jsonify({
            "status": "success",
            "message": f"Manufacturer {action}d successfully"
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# Product Routes
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        products = get_all_products()
        products_list = [format_product_response(p) for p in products]
        
        return jsonify({
            "status": "success",
            "products": products_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/verify/<serial_number>', methods=['GET'])
def verify_product_public(serial_number):
    try:
        # Get product from database
        product = get_product_by_serial(serial_number)
        
        if not product:
            return jsonify({
                "verified": False,
                "message": "Product not found"
            }), 404
        
        verification_result = {
            "verified": product["verified"],
            "blockchain_verified": product.get("blockchain_verified", False),
            "product": {
                "serial_number": serial_number,
                "name": product["name"],
                "manufacturer": product["manufacturer_name"],
                "registered_at": product["registered_at"]
            }
        }
        
        # If it's a blockchain product, verify on blockchain too
        if product.get("blockchain_verified", False):
            try:
                # Use the more detailed verification function
                blockchain_details = get_blockchain_product_details(serial_number)
                if blockchain_details:
                    verification_result["blockchain_status"] = "confirmed"
                    verification_result["blockchain_details"] = {
                        "manufacturer": blockchain_details["manufacturer"],
                        "name": blockchain_details["name"],
                        "category": blockchain_details["category"],
                        "timestamp": blockchain_details["timestamp"]
                    }
                else:
                    verification_result["blockchain_status"] = "not_found"
            except:
                verification_result["blockchain_status"] = "error"
        
        return jsonify(verification_result), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# Manufacturer Routes
@app.route('/manufacturer/register-product', methods=['POST'])
@token_required(allowed_roles=['manufacturer'])
def register_product_route(current_user_id, current_user_role):
    try:
        data = request.get_json()
        
        # Validate product data
        validate_product_data(data)
        
        # Get manufacturer info
        manufacturer = get_user_by_id(current_user_id)
        if not manufacturer:
            return jsonify({"error": "Manufacturer not found"}), 404
        
        # Check if manufacturer is authorized on blockchain
        if manufacturer.get("verification_status") != "approved":
            return jsonify({"error": "Manufacturer not verified by admin"}), 403
            
        # Optional: Also check blockchain authorization
        # blockchain_authorized = check_manufacturer_authorization(manufacturer["wallet_address"])
        # if not blockchain_authorized:
        #     return jsonify({"error": "Manufacturer not authorized on blockchain"}), 403
        
        # Prepare product data
        product_data = {
            "serial_number": data["serial_number"],
            "name": data["name"],
            "category": data["category"],
            "manufacturer_id": current_user_id,
            "manufacturer_name": manufacturer["email"],  # or company name if you have it
            "price": data.get("price", 0),
            "image_url": data.get("image_url", ""),
            "blockchain_verified": True,
            "verified": True
        }
        
        # Register on blockchain
        blockchain_result = register_product_blockchain(
            data["serial_number"],
            data["name"],
            data["category"],
            manufacturer["wallet_address"]
        )
        
        if blockchain_result and blockchain_result.get("success"):
            product_data["blockchain_tx_hash"] = blockchain_result["tx_hash"]
        else:
            return jsonify({"error": "Failed to register on blockchain"}), 500
        
        # Save to database
        product_id = create_product(product_data)
        
        return jsonify({
            "status": "success",
            "message": "Product registered successfully",
            "product_id": product_id,
            "blockchain_tx": blockchain_result.get("tx_hash")
        }), 201
        
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/manufacturer/my-products', methods=['GET'])
@token_required(allowed_roles=['manufacturer'])
def get_my_products(current_user_id, current_user_role):
    try:
        products = get_products_by_manufacturer(current_user_id)
        products_list = [format_product_response(p) for p in products]
        
        return jsonify({
            "status": "success",
            "products": products_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# Developer Routes
@app.route('/developer/create-apikey', methods=['POST'])
@token_required(allowed_roles=['developer'])
def create_apikey_route(current_user_id, current_user_role):
    try:
        data = request.get_json()
        label = data.get('label', 'API Key')
        
        api_key = create_api_key(current_user_id, label)
        
        return jsonify({
            "status": "success",
            "api_key": api_key,
            "label": label
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/developer/my-apikeys', methods=['GET'])
@token_required(allowed_roles=['developer'])
def get_my_apikeys(current_user_id, current_user_role):
    try:
        api_keys = get_api_keys_by_user(current_user_id)
        
        keys_list = []
        for key in api_keys:
            keys_list.append({
                "id": str(key["_id"]),
                "key": key["key"],
                "label": key["label"],
                "created_at": key["created_at"],
                "usage_count": key["usage_count"]
            })
        
        return jsonify({
            "status": "success",
            "api_keys": keys_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

# Simple frontend route
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Product Verification Store</title>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .product-card {
            border: 1px solid #ddd; padding: 15px; margin: 10px;
            border-radius: 8px; display: inline-block; width: 280px; vertical-align: top;
        }
        .product-image {
            position: relative; width: 100%; height: 200px;
            background-size: cover; background-position: center; border-radius: 5px;
        }
        .blockchain-badge {
            position: absolute; top: 10px; right: 10px; background: #4CAF50;
            color: white; padding: 5px 8px; border-radius: 15px; font-size: 12px; font-weight: bold;
        }
        .verify-btn {
            background: #2196F3; color: white; padding: 8px 15px;
            border: none; border-radius: 5px; cursor: pointer; margin-top: 10px;
        }
        .verified { color: green; }
        .not-verified { color: red; }
    </style>
</head>
<body>
    <h1>Product Verification Store</h1>
    <p>Blockchain Verified & Regular Products</p>
    <div id="products-container">Loading products...</div>
    
    <script>
        async function loadProducts() {
            try {
                const response = await axios.get('/api/products');
                const products = response.data.products;
                
                const container = document.getElementById('products-container');
                container.innerHTML = products.map(product => `
                    <div class="product-card">
                        <div class="product-image" style="background-image: url('${product.image_url || 'https://via.placeholder.com/280x200?text=' + encodeURIComponent(product.name)}')">
                            ${product.blockchain_verified ? '<div class="blockchain-badge">🔗 Blockchain</div>' : ''}
                        </div>
                        <h3>${product.name}</h3>
                        <p><strong>${product.price}</strong></p>
                        <p>Category: ${product.category}</p>
                        <p>Manufacturer: ${product.manufacturer_name}</p>
                        <p>Serial: ${product.serial_number}</p>
                        
                        <button class="verify-btn" onclick="verifyProduct('${product.serial_number}')">
                            ${product.blockchain_verified ? 'Verify on Blockchain' : 'Verify Authenticity'}
                        </button>
                        <div id="verification-${product.serial_number}"></div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Error loading products:', error);
                document.getElementById('products-container').innerHTML = 
                    '<p>Error loading products. Please try again later.</p>';
            }
        }
        
        async function verifyProduct(serialNumber) {
            const resultDiv = document.getElementById(`verification-${serialNumber}`);
            resultDiv.innerHTML = 'Verifying...';
            
            try {
                const response = await axios.get(`/api/verify/${serialNumber}`);
                const result = response.data;
                
                if (result.verified) {
                    let message = '<div class="verified">✅ Verified Authentic</div>';
                    if (result.blockchain_verified) {
                        message += `<small>Blockchain Status: ${result.blockchain_status || 'confirmed'}</small>`;
                    }
                    resultDiv.innerHTML = message;
                } else {
                    resultDiv.innerHTML = '<div class="not-verified">❌ Not Verified</div>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<div class="not-verified">❌ Verification Failed</div>';
                console.error('Verification error:', error);
            }
        }
        
        // Load products when page loads
        loadProducts();
    </script>
</body>
</html>
    ''')

# Health check route
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": get_current_utc(),
        "version": "1.0.0"
    }), 200

# Error handlers
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

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    )