# routes/auth_routes.py
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging
from bson import ObjectId

from services.auth_service import auth_service
from services.profile_service import profile_service
from utils.validators import validate_login_data, validate_user_registration
from middleware.auth_middleware import auth_middleware
from middleware.rate_limiting import rate_limit
# Import the functions from utils.auth
from utils.auth import authenticate_admin, authenticate_manufacturer, AuthError

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def login():
    """Generic user login endpoint"""
    try:
        data = request.get_json()
        
        validation_error = validate_login_data(data)
        if validation_error:
            return auth_middleware.create_cors_response({'error': validation_error}, 400)
        
        # Check if role is specified for specific login handling
        role = data.get('role', '').lower()
        
        if role == 'admin':
            # Use admin authentication from utils.auth
            try:
                result = authenticate_admin(data.get('email'), data.get('password'))
                return auth_middleware.create_cors_response({
                    'success': True,
                    'token': result['token'],
                    'user': result['user']
                }, 200)
            except AuthError as e:
                return auth_middleware.create_cors_response({'error': str(e)}, 401)
        
        elif role == 'manufacturer':
            # Use manufacturer authentication from utils.auth
            try:
                result = authenticate_manufacturer(data.get('email'), data.get('password'))
                return auth_middleware.create_cors_response({
                    'success': True,
                    'token': result['token'],
                    'user': result['user']
                }, 200)
            except AuthError as e:
                return auth_middleware.create_cors_response({'error': str(e)}, 401)
        
        else:
            # Use existing generic authentication
            result = auth_service.authenticate_user(data.get('email'), data.get('password'))
            
            if not result['success']:
                return auth_middleware.create_cors_response({'error': result['message']}, 401)
            
            return auth_middleware.create_cors_response({
                'success': True,
                'token': result['token'],
                'user': result['user'],
                'expires_at': result['expires_at']
            }, 200)
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return auth_middleware.create_cors_response({'error': 'Authentication failed'}, 500)

@auth_bp.route('/admin/login', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def admin_login():
    """Specific admin login endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return auth_middleware.create_cors_response({'error': 'Email and password required'}, 400)
        
        # Use authenticate_admin function from utils.auth
        result = authenticate_admin(data['email'], data['password'])
        
        return auth_middleware.create_cors_response({
            'success': True,
            'token': result['token'],
            'user': result['user']
        }, 200)
        
    except AuthError as e:
        return auth_middleware.create_cors_response({'error': str(e)}, 401)
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return auth_middleware.create_cors_response({'error': 'Login failed'}, 500)

@auth_bp.route('/manufacturer/login', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def manufacturer_login():
    """Specific manufacturer login endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return auth_middleware.create_cors_response({'error': 'Email and password required'}, 400)
        
        # Use authenticate_manufacturer function from utils.auth
        result = authenticate_manufacturer(data['email'], data['password'])
        
        return auth_middleware.create_cors_response({
            'success': True,
            'token': result['token'],
            'user': result['user']
        }, 200)
        
    except AuthError as e:
        return auth_middleware.create_cors_response({'error': str(e)}, 401)
    except Exception as e:
        logger.error(f"Manufacturer login error: {e}")
        return auth_middleware.create_cors_response({'error': 'Login failed'}, 500)

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

@auth_bp.route('/verify', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'manufacturer', 'admin'])
def verify_auth(current_user_id, current_user_role):
    """Verify if token is valid"""
    return auth_middleware.create_cors_response({
        'valid': True,
        'user': {
            'id': current_user_id,
            'role': current_user_role
        }
    }, 200)
############

@auth_bp.route('/profile', methods=['GET'])  
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'manufacturer', 'admin'])
def get_profile(current_user_id, current_user_role):
    """Get user profile for any role"""
    try:
        result = profile_service.get_user_profile(current_user_id, current_user_role)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@auth_bp.route('/manufacturer/profile', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def get_manufacturer_profile(current_user_id, current_user_role):
    """Get manufacturer-specific profile"""
    try:
        result = profile_service.get_manufacturer_profile(current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Manufacturer profile error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@auth_bp.route('/admin/profile', methods=['GET'])  # Optional: Admin-specific endpoint
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def get_admin_profile(current_user_id, current_user_role):
    """Get admin-specific profile"""
    try:
        result = profile_service.get_admin_profile(current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Admin profile error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@auth_bp.route('/update-profile', methods=['PUT'])  # Changed from '/update-profile'
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'manufacturer', 'admin'])
def update_profile(current_user_id, current_user_role):
    """Update user profile"""
    try:
        data = request.get_json()
        
        result = profile_service.update_user_profile(current_user_id, current_user_role, data)
        
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
    