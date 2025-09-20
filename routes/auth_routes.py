# routes/auth_routes.py
from flask import Blueprint, request
from datetime import datetime, timezone
import logging
from bson import ObjectId

from services.auth_service import auth_service
from services.profile_service import profile_service
from utils.validators import validate_login_data, validate_user_registration
from middleware.auth_middleware import auth_middleware
from middleware.rate_limiting import rate_limit

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        validation_error = validate_login_data(data)
        if validation_error:
            return auth_middleware.create_cors_response({'error': validation_error}, 400)
        
        result = auth_service.authenticate_user(data.get('email'), data.get('password'))
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 401)
        
        return auth_middleware.create_cors_response({
            'token': result['token'],
            'user': result['user'],
            'expires_at': result['expires_at']
        }, 200)
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return auth_middleware.create_cors_response({'error': 'Authentication failed'}, 500)

@auth_bp.route('/register', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        validation_error = validate_user_registration(data)
        if validation_error:
            return auth_middleware.create_cors_response({'error': validation_error}, 400)
        
        result = auth_service.register_user(data)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'message': result['message'],
            'user_id': result['user_id']
        }, 201)
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return auth_middleware.create_cors_response({'error': 'Registration failed'}, 500)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_cors_response({"error": "No token provided"}, 400)
        
        token = auth_header.split(' ')[1]
        result = auth_service.logout_user(token)
        
        if not result['success']:
            return auth_middleware.create_cors_response({"error": result['message']}, 500)
        
        return auth_middleware.create_cors_response({"message": "Logged out successfully"}, 200)
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return auth_middleware.create_cors_response({"error": "Logout failed"}, 500)

@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh authentication token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_cors_response({"error": "No token provided"}, 400)
        
        token = auth_header.split(' ')[1]
        result = auth_service.refresh_token(token)
        
        if not result['success']:
            return auth_middleware.create_cors_response({"error": result['message']}, 401)
        
        return auth_middleware.create_cors_response({
            'token': result['token'],
            'expires_at': result['expires_at']
        }, 200)
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return auth_middleware.create_cors_response({"error": "Token refresh failed"}, 500)

@auth_bp.route('/profile', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'manufacturer', 'admin'])
def get_profile(current_user_id, current_user_role):
    """Get user profile"""
    try:
        result = profile_service.get_user_profile(current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@auth_bp.route('/profile', methods=['PUT'])
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'manufacturer', 'admin'])
def update_profile(current_user_id, current_user_role):
    """Update user profile"""
    try:
        data = request.get_json()
        
        result = profile_service.update_user_profile(current_user_id, data)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 400)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message'],
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)