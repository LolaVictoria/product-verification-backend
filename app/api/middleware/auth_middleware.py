"""
Authentication Middleware
Simplified - only handles token extraction and validation
All business logic moved to services
"""

import logging
from functools import wraps
from flask import request, g, jsonify
from app.services.auth.token_service import token_service
from app.services.auth.auth_service import AuthError

logger = logging.getLogger(__name__)


class AuthMiddleware:
    """Middleware for authentication - token handling only"""
    
    @staticmethod
    def extract_token() -> str:
        """
        Extract JWT token from Authorization header
        
        Returns:
            Token string
            
        Raises:
            AuthError: If no token found
        """
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            raise AuthError("No authorization header")
        
        if not auth_header.startswith('Bearer '):
            raise AuthError("Invalid authorization header format")
        
        return auth_header[7:]  # Remove 'Bearer ' prefix
    
    @staticmethod
    def token_required_with_roles(allowed_roles=None):
        """
        Decorator for routes requiring authentication with specific roles
        
        Args:
            allowed_roles: List of allowed roles, or None for any authenticated user
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                try:
                    # Extract and verify token
                    token = AuthMiddleware.extract_token()
                    payload = token_service.verify_token(token)
                    
                    user_id = payload.get('sub') or payload.get('user_id')
                    user_role = payload.get('role')
                    
                    # Check role permissions
                    if allowed_roles and user_role not in allowed_roles:
                        from app.api.middleware.response_middleware import response_middleware
                        return response_middleware.create_cors_response({
                            'message': f'Access denied: requires one of {allowed_roles}'
                        }, 403)
                    
                    # Store in Flask g for route access
                    g.current_user_id = user_id
                    g.current_user_role = user_role
                    
                    # Pass to route function
                    return f(user_id, user_role, *args, **kwargs)
                    
                except AuthError as e:
                    from app.api.middleware.response_middleware import response_middleware
                    return response_middleware.create_cors_response({
                        'message': str(e)
                    }, 401)
                except Exception as e:
                    logger.error(f"Auth middleware error: {e}")
                    from app.api.middleware.response_middleware import response_middleware
                    return response_middleware.create_cors_response({
                        'message': 'Authentication failed'
                    }, 401)
            
            return wrapper
        return decorator
    
    @staticmethod
    def optional_auth(f):
        """
        Decorator for routes that work with or without authentication
        Extracts user info if token present, continues without if not
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                token = AuthMiddleware.extract_token()
                payload = token_service.verify_token(token)
                
                user_id = payload.get('sub') or payload.get('user_id')
                user_role = payload.get('role')
                
                g.current_user_id = user_id
                g.current_user_role = user_role
                
                return f(user_id, user_role, *args, **kwargs)
                
            except (AuthError, Exception):
                # No valid token - continue without auth
                return f(None, None, *args, **kwargs)
        
        return wrapper
    
    @staticmethod
    def require_auth(f):
        """
        Simple decorator requiring any authenticated user
        Alias for token_required_with_roles() with no role restrictions
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                token = AuthMiddleware.extract_token()
                payload = token_service.verify_token(token)
                
                user_id = payload.get('sub') or payload.get('user_id')
                user_role = payload.get('role')
                
                g.current_user_id = user_id
                g.current_user_role = user_role
                
                return f(user_id, user_role, *args, **kwargs)
                
            except AuthError as e:
                from app.api.middleware.response_middleware import response_middleware
                return response_middleware.create_cors_response({
                    'message': str(e)
                }, 401)
            except Exception as e:
                logger.error(f"Auth error: {e}")
                from app.api.middleware.response_middleware import response_middleware
                return response_middleware.create_cors_response({
                    'message': 'Authentication failed'
                }, 401)
        
        return wrapper

    @staticmethod
    def api_key_required(f):
        """
        Decorator for external API routes requiring API key authentication
        Used for programmatic access (not dashboard users)
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # Extract API key from header
                api_key = request.headers.get('X-API-Key')
                
                if not api_key:
                    return jsonify({
                        'success': False,
                        'error': 'API key required'
                    }), 401
                
                # Validate API key
                from app.services.manufacturer.api_key_service import api_key_service
                validation = api_key_service.validate_api_key(api_key)
                
                if not validation.get('valid'):
                    return jsonify({
                        'success': False,
                        'error': 'Invalid API key'
                    }), 401
                
                # Store API key data in request context
                request.api_key_data = validation
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"API key validation error: {e}")
                return jsonify({
                    'success': False,
                    'error': 'API authentication failed'
                }), 401
        
        return wrapper

auth_middleware = AuthMiddleware()