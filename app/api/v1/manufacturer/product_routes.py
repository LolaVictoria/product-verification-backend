"""
Manufacturer Product Routes
Product CRUD operations, bulk management, and ownership transfer
"""
from flask import Blueprint, request
import logging

from app.services.manufacturer.product_service import product_service
from app.validators.product_validator import ProductValidator
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.rate_limiting import rate_limit
from app.services.access_control_service import access_control_service

product_bp = Blueprint('manufacturer_products', __name__)
logger = logging.getLogger(__name__)


@product_bp.route('', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_products(current_user_id, current_user_role):
    """Get manufacturer's products with pagination and filters"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        
        # Query parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        filter_type = request.args.get('filter', 'all')
        search = request.args.get('search', '')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        result = product_service.get_manufacturer_products(
            manufacturer_id=manufacturer_id,
            page=page,
            limit=limit,
            filter_type=filter_type,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get products'
        }, 500)


@product_bp.route('/<product_id>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_product(current_user_id, current_user_role, product_id):
    """Get specific product details"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        result = product_service.get_product_by_id(product_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get product error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get product'
        }, 500)


@product_bp.route('', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
@rate_limit({'per_minute': 30, 'per_hour': 500})
def register_product(current_user_id, current_user_role):
    """Register a new product"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        # Validate product data
        validation_result = ProductValidator.validate_product_data(data)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }, 400)
        
        result = product_service.register_product(manufacturer_id, data)
        
        status_code = 201 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Product registration error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to register product'
        }, 500)


@product_bp.route('/<product_id>', methods=['PUT'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def update_product(current_user_id, current_user_role, product_id):
    """Update existing product"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        result = product_service.update_product(product_id, data)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Update product error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to update product'
        }, 500)


@product_bp.route('/<product_id>', methods=['DELETE'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def delete_product(current_user_id, current_user_role, product_id):
    """Delete product"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        result = product_service.delete_product(product_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Delete product error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to delete product'
        }, 500)


@product_bp.route('/bulk-import', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def bulk_import_products(current_user_id, current_user_role):
    """Bulk import products from CSV/JSON"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        
        # Check for file upload or JSON data
        if 'file' in request.files:
            file = request.files['file']
            result = product_service.bulk_import_from_file(manufacturer_id, file)
        else:
            data = request.get_json()
            if not data or 'products' not in data:
                return response_middleware.create_cors_response({
                    'success': False,
                    'error': 'Products array required'
                }, 400)
            result = product_service.bulk_import_from_json(manufacturer_id, data['products'])
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Bulk import error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Bulk import failed'
        }, 500)


@product_bp.route('/transfer-ownership', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def transfer_ownership(current_user_id, current_user_role):
    """Transfer product ownership"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        # Validate transfer data
        validation_result = ProductValidator.validate_ownership_transfer(data)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }, 400)
        
        result = product_service.transfer_ownership(manufacturer_id, data)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Transfer ownership error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to transfer ownership'
        }, 500)


@product_bp.route('/<product_id>/blockchain-confirm', methods=['PUT'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def confirm_blockchain_registration(current_user_id, current_user_role, product_id):
    """Confirm blockchain registration for a product"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        data = request.get_json()
        
        if not data or 'transaction_hash' not in data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Transaction hash required'
            }, 400)
        
        result = product_service.confirm_blockchain_registration(product_id, data)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Blockchain confirmation error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to confirm blockchain registration'
        }, 500)


@product_bp.route('/<product_id>/blockchain-failed', methods=['PUT'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def mark_blockchain_failed(current_user_id, current_user_role, product_id):
    """Mark blockchain registration as failed"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        data = request.get_json()
        error_message = data.get('error', 'Unknown error') if data else 'Unknown error'
        
        result = product_service.mark_blockchain_failed(product_id, error_message)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Mark blockchain failed error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to update blockchain status'
        }, 500)