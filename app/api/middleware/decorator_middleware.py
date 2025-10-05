"""
Decorator Middleware
Combines multiple middleware decorators for common endpoint patterns
"""
import logging
from functools import wraps
from flask import request

from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.logging_middleware import logging_middleware
from app.api.middleware.validation_middleware import validation_middleware

logger = logging.getLogger(__name__)


class DecoratorsMiddleware:
    """Combines common middleware patterns"""
    
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
        return DecoratorsMiddleware.api_endpoint(
            logging_middleware.log_request_response,
            validation_middleware.validate_json_required,
            auth_middleware.token_required_with_roles(allowed_roles)
        )
    
    @staticmethod
    def public_api_endpoint():
        """Common decorator for public API endpoints"""
        return DecoratorsMiddleware.api_endpoint(
            logging_middleware.log_request_response,
            validation_middleware.validate_json_required
        )
    
    @staticmethod
    def validate_content_size(max_size_mb=10):
        """Validate request content length"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                content_length = request.content_length
                if content_length and content_length > max_size_mb * 1024 * 1024:
                    return response_middleware.create_cors_response({
                        'error': f'Request too large. Maximum size: {max_size_mb}MB'
                    }, 413)
                return f(*args, **kwargs)
            return decorated
        return decorator


decorators_middleware = DecoratorsMiddleware()