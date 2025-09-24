from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging
from bson import ObjectId

from services.manufacturer_service import manufacturer_service
from services.verification_service import verification_service
from utils.validators import validate_product_data
from middleware.auth_middleware import auth_middleware
from utils.helpers import format_product_response

logger = logging.getLogger(__name__)

product_bp = Blueprint('products', __name__, url_prefix='/products')

@product_bp.route('/get-products', methods=['GET'])
@auth_middleware.optional_auth
def get_products(current_user_id, current_user_role):
    """Get products list with optional filtering"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        manufacturer_id = request.args.get('manufacturer_id')
        search = request.args.get('search')
        
        result = manufacturer_service.get_products_list(
            page=page,
            limit=limit,
            manufacturer_id=manufacturer_id,
            search=search,
            current_user_id=current_user_id,
            current_user_role=current_user_role
        )
        
        return auth_middleware.create_cors_response(result)
        
    except Exception as e:
        logger.error(f"Error getting products: {e}")
        return auth_middleware.create_error_response("Failed to get products")

@product_bp.route('/products/<product_id>', methods=['GET'])
@auth_middleware.optional_auth
def get_product(current_user_id, current_user_role, product_id):
    """Get specific product details"""
    try:
        product = manufacturer_service.get_product_by_id(product_id)
        if not product:
            return auth_middleware.create_error_response("Product not found", 404)
        
        # Check access permissions
        if not manufacturer_service.can_access_product(product, current_user_id, current_user_role):
            return auth_middleware.create_error_response("Access denied", 403)
        
        return auth_middleware.create_cors_response({
            'product': format_product_response(product)
        })
        
    except Exception as e:
        logger.error(f"Error getting product {product_id}: {e}")
        return auth_middleware.create_error_response("Failed to get product")

@product_bp.route('/products', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def create_product(current_user_id, current_user_role):
    """Create new product"""
    try:
        data = request.get_json()
        if not data:
            return auth_middleware.create_error_response("No data provided")
        
        # Validate product data
        validation_error = validate_product_data(data)
        if validation_error:
            return auth_middleware.create_error_response(validation_error)
        
        result = manufacturer_service.create_product(data, current_user_id)
        
        if result['success']:
            return auth_middleware.create_cors_response({
                'message': 'Product created successfully',
                'product': result['product']
            }, 201)
        else:
            return auth_middleware.create_error_response(result['error'])
        
    except Exception as e:
        logger.error(f"Error creating product: {e}")
        return auth_middleware.create_error_response("Failed to create product")

@product_bp.route('/products/<product_id>', methods=['PUT'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def update_product(current_user_id, current_user_role, product_id):
    """Update existing product"""
    try:
        data = request.get_json()
        if not data:
            return auth_middleware.create_error_response("No data provided")
        
        result = manufacturer_service.update_product(product_id, data, current_user_id)
        
        if result['success']:
            return auth_middleware.create_cors_response({
                'message': 'Product updated successfully',
                'product': result['product']
            })
        else:
            return auth_middleware.create_error_response(result['error'])
        
    except Exception as e:
        logger.error(f"Error updating product {product_id}: {e}")
        return auth_middleware.create_error_response("Failed to update product")

@product_bp.route('/products/<product_id>', methods=['DELETE'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def delete_product(current_user_id, current_user_role, product_id):
    """Delete product"""
    try:
        result = manufacturer_service.delete_product(product_id, current_user_id)
        
        if result['success']:
            return auth_middleware.create_cors_response({
                'message': 'Product deleted successfully'
            })
        else:
            return auth_middleware.create_error_response(result['error'])
        
    except Exception as e:
        logger.error(f"Error deleting product {product_id}: {e}")
        return auth_middleware.create_error_response("Failed to delete product")

@product_bp.route('/products/bulk-import', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def bulk_import_products(current_user_id, current_user_role):
    """Bulk import products from CSV/JSON"""
    try:
        if 'file' in request.files:
            file = request.files['file']
            result = manufacturer_service.bulk_import_from_file(file, current_user_id)
        else:
            data = request.get_json()
            result = manufacturer_service.bulk_import_from_json(data, current_user_id)
        
        if result['success']:
            return auth_middleware.create_cors_response({
                'message': f"Successfully imported {result['imported_count']} products",
                'failed_count': result.get('failed_count', 0),
                'errors': result.get('errors', [])
            })
        else:
            return auth_middleware.create_error_response(result['error'])
        
    except Exception as e:
        logger.error(f"Error bulk importing products: {e}")
        return auth_middleware.create_error_response("Failed to import products")