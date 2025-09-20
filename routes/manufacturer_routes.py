# routes/manufacturer_routes.py
from flask import Blueprint, request
from datetime import datetime, timezone
import logging
from bson import ObjectId

from services.manufacturer_service import manufacturer_service
from services.product_service import product_service
from utils.validators import validate_product_data
from middleware.auth_middleware import auth_middleware
from middleware.rate_limiting import rate_limit

manufacturer_bp = Blueprint('manufacturer', __name__)
logger = logging.getLogger(__name__)

@manufacturer_bp.route('/dashboard/stats', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def get_dashboard_stats(current_user_id, current_user_role):
    """Get manufacturer dashboard statistics"""
    try:
        result = manufacturer_service.get_dashboard_stats(current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response(result['data'], 200)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/products', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def get_products(current_user_id, current_user_role):
    """Get manufacturer's products"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        filter_type = request.args.get('filter', 'all')
        
        result = product_service.get_manufacturer_products(
            current_user_id, page, limit, filter_type
        )
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response(result['data'], 200)
        
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/products', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
@rate_limit({'per_minute': 30, 'per_hour': 500})
def register_product(current_user_id, current_user_role):
    """Register a new product"""
    try:
        data = request.get_json()
        
        validation_error = validate_product_data(data)
        if validation_error:
            return auth_middleware.create_cors_response({'error': validation_error}, 400)
        
        result = product_service.register_product(current_user_id, data)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message'],
            'product_id': result['product_id'],
            'serial_number': result['serial_number']
        }, 201)
        
    except Exception as e:
        logger.error(f"Product registration error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/products/<product_id>/blockchain-confirm', methods=['PUT'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def confirm_blockchain_registration(current_user_id, current_user_role, product_id):
    """Confirm blockchain registration for a product"""
    try:
        data = request.get_json()
        
        result = product_service.confirm_blockchain_registration(
            current_user_id, product_id, data
        )
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'success': True,
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Blockchain confirmation error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/products/<product_id>/blockchain-failed', methods=['PUT'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def mark_blockchain_failed(current_user_id, current_user_role, product_id):
    """Mark blockchain registration as failed"""
    try:
        data = request.get_json()
        
        result = product_service.mark_blockchain_failed(
            current_user_id, product_id, data.get('error')
        )
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'success': True,
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Mark blockchain failed error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/products/transfer-ownership', methods=['PUT'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def transfer_ownership(current_user_id, current_user_role):
    """Transfer product ownership"""
    try:
        data = request.get_json()
        
        result = product_service.transfer_ownership(current_user_id, data)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'success': True,
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Transfer ownership error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def get_api_keys(current_user_id, current_user_role):
    """Get manufacturer's API keys"""
    try:
        result = manufacturer_service.get_api_keys(current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'api_keys': result['api_keys']
        }, 200)
        
    except Exception as e:
        logger.error(f"Get API keys error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def create_api_key(current_user_id, current_user_role):
    """Create new API key"""
    try:
        data = request.get_json()
        
        result = manufacturer_service.create_api_key(current_user_id, data)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response(result['data'], 201)
        
    except Exception as e:
        logger.error(f"Create API key error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys/<key_id>/revoke', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def revoke_api_key(current_user_id, current_user_role, key_id):
    """Revoke an API key"""
    try:
        result = manufacturer_service.revoke_api_key(current_user_id, key_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Revoke API key error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)