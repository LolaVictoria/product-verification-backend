from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from datetime import datetime
from bson import ObjectId
from models import User, Product
from utils.decorators import require_role
from utils.validators import validate_serial_number, validate_product_name, validate_category, validate_pagination
from utils.helpers import create_error_response, create_success_response, format_pagination_response
import logging

logger = logging.getLogger(__name__)

manufacturer_bp = Blueprint('manufacturer', __name__)

@manufacturer_bp.route('/register-product', methods=['POST'])
@require_role('manufacturer')
def register_product():
    """Register a new product"""
    try:
        user_id = get_jwt_identity()
        user = User.find_by_id(user_id)
        
        if not user or not user.get('wallet_address'):
            return create_error_response('Wallet address not found', 400)
        
        data = request.get_json()
        if not data:
            return create_error_response('No data provided')
        
        serial_number = data.get('serial_number', '').strip()
        product_name = data.get('product_name', '').strip()
        category = data.get('category', '').strip()
        description = data.get('description', '').strip()
        
        # Validate input
        if not validate_serial_number(serial_number):
            return create_error_response('Invalid serial number format')
        
        if not validate_product_name(product_name):
            return create_error_response('Invalid product name')
        
        if not validate_category(category):
            return create_error_response('Invalid category')
        
        # Check if product already exists
        if Product.serial_exists(serial_number):
            return create_error_response('Product with this serial number already exists')
        
        # Register on blockchain
        from app import blockchain_service
        wallet_address = user['wallet_address']
        
        blockchain_result = blockchain_service.register_product(
            serial_number, product_name, category, wallet_address
        )
        
        if not blockchain_result['success']:
            return create_error_response(f'Blockchain registration failed: {blockchain_result.get("error")}', 500)
        
        # Store in MongoDB
        result = Product.create_product(
            serial_number, product_name, category, description,
            user_id, wallet_address, blockchain_result['tx_hash']
        )
        
        return create_success_response(
            'Product registered successfully',
            {
                'product_id': str(result.inserted_id),
                'serial_number': serial_number,
                'tx_hash': blockchain_result['tx_hash']
            },
            201
        )
        
    except Exception as e:
        logger.error(f"Product registration error: {e}")
        return create_error_response('Internal server error', 500)

@manufacturer_bp.route('/my-products', methods=['GET'])
@require_role('manufacturer')
def get_manufacturer_products():
    """Get manufacturer's products with pagination"""
    try:
        user_id = get_jwt_identity()
        
        # Get and validate pagination parameters
        page, per_page = validate_pagination(
            request.args.get('page'),
            request.args.get('per_page')
        )
        
        # Query products
        products, total = Product.find_by_manufacturer(user_id, page, per_page)
        
        response = format_pagination_response(products, page, per_page, total)
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return create_error_response('Internal server error', 500)

@manufacturer_bp.route('/product/<serial_number>', methods=['GET'])
@require_role('manufacturer')
def get_product_details(serial_number):
    """Get detailed information about a specific product"""
    try:
        user_id = get_jwt_identity()
        
        if not validate_serial_number(serial_number):
            return create_error_response('Invalid serial number format')
        
        product = Product.find_by_serial_number(serial_number)
        
        if not product:
            return create_error_response('Product not found', 404)
        
        # Check if user owns this product
        if str(product['manufacturer_id']) != user_id:
            return create_error_response('Access denied', 403)
        
        return jsonify({'product': product}), 200
        
    except Exception as e:
        logger.error(f"Get product details error: {e}")
        return create_error_response('Internal server error', 500)

@manufacturer_bp.route('/product/<product_id>', methods=['PUT'])
@require_role('manufacturer')
def update_product(product_id):
    """Update product information (limited fields)"""
    try:
        from bson import ObjectId
        user_id = get_jwt_identity()
        
        data = request.get_json()
        if not data:
            return create_error_response('No data provided')
        
        # Find product
        product = Product.collection.find_one({
            '_id': ObjectId(product_id),
            'manufacturer_id': ObjectId(user_id)
        })
        
        if not product:
            return create_error_response('Product not found', 404)
        
        # Only allow updating description
        update_data = {}
        if 'description' in data:
            description = data['description'].strip()
            if len(description) <= 500:  # Max description length
                update_data['description'] = description
        
        if not update_data:
            return create_error_response('No valid fields to update')
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = Product.collection.update_one(
            {'_id': ObjectId(product_id)},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return create_error_response('Product not updated')
        
        return create_success_response('Product updated successfully')
        
    except Exception as e:
        logger.error(f"Update product error: {e}")
        return create_error_response('Internal server error', 500)