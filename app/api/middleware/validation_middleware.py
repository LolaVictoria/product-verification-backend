"""
Validation Middleware
Request validation and data sanitization
"""
import logging
from functools import wraps
from flask import request

from app.api.middleware.response_middleware import response_middleware

logger = logging.getLogger(__name__)


class ValidationMiddleware:
    """Middleware for request validation"""
    
    @staticmethod
    def validate_json_required(f):
        """Decorator to ensure request has JSON body"""
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                return response_middleware.create_cors_response({
                    'success': False,
                    'error': 'Content-Type must be application/json'
                }, 400)
            
            data = request.get_json()
            if not data:
                return response_middleware.create_cors_response({
                    'success': False,
                    'error': 'Request body is required'
                }, 400)
            
            return f(*args, **kwargs)
        
        return wrapper
    
    @staticmethod
    def validate_required_fields(required_fields):
        """
        Decorator to validate required fields in JSON body
        
        Args:
            required_fields: List of required field names
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                data = request.get_json()
                
                if not data:
                    return response_middleware.create_cors_response({
                        'success': False,
                        'error': 'Request body is required'
                    }, 400)
                
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    return response_middleware.create_cors_response({
                        'success': False,
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }, 400)
                
                return f(*args, **kwargs)
            
            return wrapper
        return decorator
    
    @staticmethod
    def sanitize_input(data):
        """
        Sanitize user input to prevent injection attacks
        
        Args:
            data: Input data (string, dict, or list)
            
        Returns:
            Sanitized data
        """
        if isinstance(data, str):
            # Remove potential XSS/injection characters
            dangerous_chars = ['<', '>', '"', "'", ';', '&', '$', '`']
            for char in dangerous_chars:
                data = data.replace(char, '')
            return data.strip()
        
        elif isinstance(data, dict):
            return {k: ValidationMiddleware.sanitize_input(v) for k, v in data.items()}
        
        elif isinstance(data, list):
            return [ValidationMiddleware.sanitize_input(item) for item in data]
        
        return data
    
    @staticmethod
    def validate_pagination_params():
        """Validate and sanitize pagination parameters"""
        try:
            page = max(1, int(request.args.get('page', 1)))
            limit = max(1, min(100, int(request.args.get('limit', 20))))
            
            return {
                'page': page,
                'limit': limit,
                'skip': (page - 1) * limit
            }
        except ValueError:
            return {
                'page': 1,
                'limit': 20,
                'skip': 0
            }
    
    @staticmethod
    def validate_file_upload(allowed_extensions=None):
        """
        Decorator to validate file uploads
        
        Args:
            allowed_extensions: List of allowed file extensions (e.g., ['csv', 'json'])
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                if 'file' not in request.files:
                    return response_middleware.create_cors_response({
                        'success': False,
                        'error': 'No file uploaded'
                    }, 400)
                
                file = request.files['file']
                
                if file.filename == '':
                    return response_middleware.create_cors_response({
                        'success': False,
                        'error': 'No file selected'
                    }, 400)
                
                if allowed_extensions:
                    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                    
                    if file_ext not in allowed_extensions:
                        return response_middleware.create_cors_response({
                            'success': False,
                            'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'
                        }, 400)
                
                return f(*args, **kwargs)
            
            return wrapper
        return decorator


validation_middleware = ValidationMiddleware()