"""
Manufacturer API Key Routes
API key creation, management, and revocation
"""
from flask import Blueprint, request
import logging

from app.services.manufacturer.api_key_service import api_key_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.rate_limiting import rate_limit
from app.services.access_control_service import access_control_service

api_key_bp = Blueprint('manufacturer_api_keys', __name__)
logger = logging.getLogger(__name__)


@api_key_bp.route('', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_api_keys(current_user_id, current_user_role):
    """Get manufacturer's API keys"""
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
        result = api_key_service.get_api_keys(manufacturer_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get API keys error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get API keys'
        }, 500)


@api_key_bp.route('/<key_id>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_api_key(current_user_id, current_user_role, key_id):
    """Get specific API key details"""
    try:
        access_check = access_control_service.can_access_api_key(
            current_user_id, current_user_role, key_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        result = api_key_service.get_api_key_by_id(key_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get API key error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get API key'
        }, 500)


@api_key_bp.route('', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def create_api_key(current_user_id, current_user_role):
    """Create new API key"""
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
        data = request.get_json() or {}
        
        result = api_key_service.create_api_key(manufacturer_id, data)
        
        status_code = 201 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Create API key error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to create API key'
        }, 500)


@api_key_bp.route('/<key_id>', methods=['PUT'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def update_api_key(current_user_id, current_user_role, key_id):
    """Update API key (name, permissions)"""
    try:
        access_check = access_control_service.can_access_api_key(
            current_user_id, current_user_role, key_id
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
        
        result = api_key_service.update_api_key(key_id, data)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Update API key error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to update API key'
        }, 500)


@api_key_bp.route('/<key_id>/revoke', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def revoke_api_key(current_user_id, current_user_role, key_id):
    """Revoke an API key"""
    try:
        access_check = access_control_service.can_access_api_key(
            current_user_id, current_user_role, key_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        result = api_key_service.revoke_api_key(key_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Revoke API key error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to revoke API key'
        }, 500)


@api_key_bp.route('/<key_id>/regenerate', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
@rate_limit({'per_minute': 3, 'per_hour': 10})
def regenerate_api_key(current_user_id, current_user_role, key_id):
    """Regenerate API key (creates new key, revokes old one)"""
    try:
        access_check = access_control_service.can_access_api_key(
            current_user_id, current_user_role, key_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        result = api_key_service.regenerate_api_key(key_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Regenerate API key error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to regenerate API key'
        }, 500)


@api_key_bp.route('/<key_id>/usage', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_api_key_usage(current_user_id, current_user_role, key_id):
    """Get API key usage statistics"""
    try:
        access_check = access_control_service.can_access_api_key(
            current_user_id, current_user_role, key_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        time_range = request.args.get('time_range', '30d')
        result = api_key_service.get_api_key_usage(key_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get API key usage error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get API key usage'
        }, 500)