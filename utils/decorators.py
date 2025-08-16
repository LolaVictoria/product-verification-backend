from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
# from services.auth_service import AuthService

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from services.auth_service import AuthService
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        request_info = {
            'endpoint': request.endpoint,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        key_doc = AuthService.verify_api_key(api_key, request_info)
        if not key_doc:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Add key info to request context
        request.api_key_info = key_doc
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(required_role):
    """Decorator to require specific user role"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            from services.auth_service import AuthService
            claims = get_jwt()
            user_role = claims.get('role')
            
            if user_role != required_role:
                return jsonify({'error': f'{required_role.title()} role required'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator