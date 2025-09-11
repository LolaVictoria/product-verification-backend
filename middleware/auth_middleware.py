from flask import request, jsonify, make_response
from functools import wraps
import jwt
from datetime import datetime, timezone
from bson import ObjectId
from config.__init__ import DatabaseConfig
import os
import logging

def configure_cors(app):
    """Configure CORS for the Flask app"""
    from flask_cors import CORS
    
    # CORS origins from environment or defaults
    cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
    
    CORS(app, 
         origins=cors_origins,
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         supports_credentials=True
    )
    
    return app

class AuthMiddleware:
    @staticmethod
    def add_cors_headers(response):
        """Add comprehensive CORS headers to any response"""
        origin = request.headers.get('Origin')
        allowed_origins = [
            'http://localhost:3000',
            'http://localhost:5173',
            'http://127.0.0.1:5173',
            'https://blockchain-verification-esup.vercel.app'
        ]
        
        if origin not in allowed_origins:
            return make_response(jsonify({'message': 'Origin not allowed'}), 403)
        
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Requested-With,X-API-Key,Accept,Origin,Cache-Control,Pragma'
        response.headers['Access-Control-Expose-Headers'] = 'Authorization,X-Total-Count'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Max-Age'] = '86400'
        return response

    @staticmethod
    def create_cors_response(data, status_code=200):
        """Helper function to create CORS-enabled responses"""
        response = make_response(jsonify(data), status_code)
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
    def token_required(allowed_roles=None):
        """Decorator for routes requiring JWT authentication"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                token = request.headers.get('Authorization')
                
                if not token:
                    return AuthMiddleware.create_cors_response({'message': 'Token is missing'}, 401)
                
                # Validate token
                user_id, user_role, error, status = AuthMiddleware.validate_jwt_token(token, os.getenv('SECRET_KEY'))
                if error:
                    return AuthMiddleware.create_cors_response(error, status)
                
                # Check if token is blacklisted
                db = DatabaseConfig.get_db_connection()
                blacklisted = db.blacklisted_tokens.find_one({"token": token})
                if blacklisted:
                    return AuthMiddleware.create_cors_response({'message': 'Token has been revoked'}, 401)
                
                # Check role authorization
                if allowed_roles and user_role not in allowed_roles:
                    return AuthMiddleware.create_cors_response({
                        'message': f'Access denied: requires one of {allowed_roles}'
                    }, 403)
                
                return f(user_id, user_role, *args, **kwargs)
            return decorated
        return decorator

    @staticmethod
    def api_key_required(f):
        """Decorator for API key authentication"""
        @wraps(f)
        def decorator(*args, **kwargs):
            api_key = request.headers.get('X-API-Key') or request.headers.get('x-api-key')
            
            if not api_key:
                return AuthMiddleware.create_cors_response({'message': 'API key is required'}, 401)
            
            # Validate API key using manufacturer service
            manufacturer_service = manufacturer_service
            key_data = manufacturer_service.validate_api_key(api_key)
            
            if not key_data:
                return AuthMiddleware.create_cors_response({'message': 'Invalid API key'}, 401)
            
            request.api_key_data = key_data
            return f(*args, **kwargs)
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
    def public_api_endpoint():
        """Common decorator for public API endpoints"""
        return AuthMiddleware.api_endpoint(
            AuthMiddleware.log_request_response,
            AuthMiddleware.rate_limit_check,
            AuthMiddleware.validate_content_type
        )

    @staticmethod
    def integration_api_endpoint():
        """Common decorator for integration API endpoints"""
        return AuthMiddleware.api_endpoint(
            AuthMiddleware.log_request_response,
            AuthMiddleware.rate_limit_check,
            AuthMiddleware.validate_content_type,
            AuthMiddleware.api_key_required
        )

auth_middleware = AuthMiddleware()