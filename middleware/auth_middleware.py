from flask import request, jsonify, make_response, current_app
from functools import wraps
import os
import jwt
from datetime import datetime, timezone
from bson import ObjectId
import logging
from utils.validators import validate_token
from typing import Any

class AuthMiddleware:
    @staticmethod
    def add_cors_headers(response):
        """Add CORS headers to a response"""
        allowed_origins = [
            'http://localhost:3000',
            'http://localhost:5173',  # Your frontend URL
            'https://blockchain-verification-esup.vercel.app'
        ]
        
        origin = request.headers.get('Origin')
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = allowed_origins[0]
        
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-API-Key'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    
    @staticmethod
    def create_cors_response(data, status_code=200):
        """Helper function to create CORS-enabled responses"""
        response = make_response(jsonify(data), status_code)
        return AuthMiddleware.add_cors_headers(response)
    
    @staticmethod
    def create_success_response(data: Any = None, message: str = "Operation successful", status_code: int = 200) -> Any:
        """
        Create a standardized success response with CORS headers.
        """
        response_data = {
            'success': True,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if data is not None:
            response_data['data'] = data
        
        # Create response with CORS headers
        response = make_response(jsonify(response_data), status_code)
        return AuthMiddleware.add_cors_headers(response)
   
    @staticmethod
    def create_error_response(error: str, status_code: int = 400, error_code: str = None, details: Any = None) -> Any:
        """
        Create a standardized error response with CORS headers.
        """
        response_data = {
            'success': False,
            'error': error,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if error_code:
            response_data['error_code'] = error_code
        if details is not None:
            response_data['details'] = details
        
        # Create response with CORS headers
        response = make_response(jsonify(response_data), status_code)
        return AuthMiddleware.add_cors_headers(response)

    @staticmethod
    def validate_jwt_token(token, secret_key):
            """Validate JWT token and return user info"""
            if not token:
                return None, None, {'message': 'Token is missing!'}, 401
            
            if token.startswith('Bearer '):
                token = token[7:]
                
            try:
                data = jwt.decode(token, secret_key, algorithms=['HS256'])
                if 'sub' not in data or 'role' not in data:
                    return None, None, {'message': 'Invalid token: missing required fields'}, 401
                return ObjectId(data['sub']), data['role'], None, None
            except jwt.ExpiredSignatureError:
                return None, None, {'message': 'Token has expired!'}, 401
            except jwt.InvalidTokenError:
                return None, None, {'message': 'Token is invalid!'}, 401
            except Exception:
                return None, None, {'message': 'Token validation failed'}, 401

    @staticmethod
    def token_required(allowed_roles):
            """Decorator for routes requiring specific roles"""
            def decorator(f):
                @wraps(f)
                def decorated(*args, **kwargs):
                    token = request.headers.get('Authorization')
                    user_id, user_role, error, status = AuthMiddleware.validate_jwt_token(token, os.getenv('SECRET_KEY'))
                    if error:
                        return AuthMiddleware.create_cors_response(error, status)
                    if allowed_roles and user_role not in allowed_roles:
                        return AuthMiddleware.create_cors_response({'message': f'Access denied: requires one of {allowed_roles}'}, 403)
                    return f(user_id, user_role, *args, **kwargs)
                return decorated
            return decorator

    @staticmethod
    def api_key_required(manufacturer_service):
            """Decorator for API key authentication"""
            def decorator(f):
                @wraps(f)
                def decorated(*args, **kwargs):
                    api_key = request.headers.get('X-API-Key') or request.headers.get('x-api-key')
                    
                    if not api_key:
                        return AuthMiddleware.create_cors_response({'message': 'API key is required'}, 401)
                    
                    key_data = manufacturer_service.validate_api_key(api_key)
                    
                    if not key_data:
                        return AuthMiddleware.create_cors_response({'message': 'Invalid API key'}, 401)
                    
                    request.api_key_data = key_data
                    return f(*args, **kwargs)
                return decorated
            return decorator

    @staticmethod
    def rate_limit_check(f):
            """Basic rate limiting decorator"""
            @wraps(f)
            def decorator(*args, **kwargs):
                client_id = request.headers.get('X-API-Key', request.remote_addr)
                current_time = datetime.now(timezone.utc)
                
                if hasattr(request, 'api_key_data'):
                    rate_limits = request.api_key_data.get('rate_limits', {})
                    requests_per_minute = rate_limits.get('requests_per_minute', 100)
                    logging.info(f"Rate limit check for {client_id}: {requests_per_minute}/minute")
                
                return f(*args, **kwargs)
            return decorator

    @staticmethod
    def log_request_response(f):
            """Middleware to log requests and responses"""
            @wraps(f)
            def decorator(*args, **kwargs):
                start_time = datetime.now(timezone.utc)
                request_data = {
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'timestamp': start_time.isoformat()
                }
                
                if hasattr(request, 'api_key_data'):
                    request_data['manufacturer_id'] = request.api_key_data.get('manufacturer_id')
                    request_data['company_name'] = request.api_key_data.get('company_name')
                
                try:
                    response = f(*args, **kwargs)
                    response_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                    logging.info(f"API Request: {request_data} - {response_time:.3f}s")
                    return response
                except Exception as e:
                    logging.error(f"API Error: {request_data} - {str(e)}")
                    return AuthMiddleware.create_cors_response({'message': 'Internal server error'}, 500)
            return decorator

    @staticmethod
    def validate_content_type(f):
            """Ensure requests have proper content type for POST/PUT requests"""
            @wraps(f)
            def decorator(*args, **kwargs):
                if request.method in ['POST', 'PUT', 'PATCH']:
                    content_type = request.headers.get('Content-Type', '')
                    if not content_type.startswith('application/json'):
                        return AuthMiddleware.create_cors_response({
                            'error': 'Content-Type must be application/json'
                        }, 400)
                return f(*args, **kwargs)
            return decorator

    @staticmethod
    def api_endpoint(*decorators):
            """Combine multiple decorators for API endpoints"""
            def decorator(f):
                for d in reversed(decorators):
                    f = d(f)
                return f
            return decorator

    @staticmethod
    def authenticated_api_endpoint(allowed_roles=None):
            """Common decorator for authenticated API endpoints"""
            return AuthMiddleware.api_endpoint(
                AuthMiddleware.log_request_response,
                AuthMiddleware.rate_limit_check,
                AuthMiddleware.validate_content_type,
                AuthMiddleware.token_required(allowed_roles)
            )
        
    @staticmethod
    def token_required_with_roles(allowed_roles):
            """Decorator for routes requiring specific roles"""
            def decorator(f):
                @wraps(f)
                def decorated(*args, **kwargs):
                    token = request.headers.get('Authorization')
                    user_id, user_role, error, status = AuthMiddleware.validate_jwt_token(token, current_app.config['SECRET_KEY'])
                    if error:
                        return AuthMiddleware.create_cors_response(error, status)
                    if allowed_roles and user_role not in allowed_roles:
                        return AuthMiddleware.create_cors_response({'message': f'Access denied: requires one of {allowed_roles}'}, 403)
                    return f(user_id, user_role, *args, **kwargs)
                return decorated
            return decorator

    @staticmethod
    def public_api_endpoint():
            """Common decorator for public API endpoints"""
            return AuthMiddleware.api_endpoint(
                AuthMiddleware.log_request_response,
                AuthMiddleware.rate_limit_check,
                AuthMiddleware.validate_content_type
            )

    @staticmethod
    def integration_api_endpoint(manufacturer_service):
            """Common decorator for integration API endpoints"""
            return AuthMiddleware.api_endpoint(
                AuthMiddleware.log_request_response,
                AuthMiddleware.rate_limit_check,
                AuthMiddleware.validate_content_type,
                AuthMiddleware.api_key_required(manufacturer_service)
            )





























auth_middleware = AuthMiddleware()