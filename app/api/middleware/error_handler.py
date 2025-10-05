"""
Error Handler Middleware
Centralized error handling for the application
"""

import logging
import traceback
from flask import jsonify, request
from werkzeug.exceptions import HTTPException

from app.api.middleware.response_middleware import response_middleware
from app.services.auth.auth_service import AuthError
from app.validators.auth_validator import AuthValidator

logger = logging.getLogger(__name__)


class ErrorHandler:
    """Centralized error handling"""
    
    @staticmethod
    def init_app(app):
        """Initialize error handlers for Flask app"""
        
        # Authentication errors
        @app.errorhandler(AuthError)
        def handle_auth_error(error):
            logger.warning(f"Authentication error: {str(error)} - {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Authentication failed',
                'message': str(error)
            }, 401)
        
        # Validation errors
        @app.errorhandler(ValueError)
        def handle_validation_error(error):
            logger.warning(f"Validation error: {str(error)} - {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Validation failed',
                'message': str(error)
            }, 400)
        
        # HTTP exceptions
        @app.errorhandler(HTTPException)
        def handle_http_exception(error):
            logger.info(f"HTTP {error.code}: {request.path}")
            return response_middleware.create_cors_response({
                'error': error.name,
                'message': error.description
            }, error.code)
        
        # 400 Bad Request
        @app.errorhandler(400)
        def bad_request(error):
            logger.warning(f"400 Bad Request: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Bad request',
                'message': 'Invalid request data or parameters'
            }, 400)
        
        # 401 Unauthorized
        @app.errorhandler(401)
        def unauthorized(error):
            logger.warning(f"401 Unauthorized: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Unauthorized',
                'message': 'Authentication required'
            }, 401)
        
        # 403 Forbidden
        @app.errorhandler(403)
        def forbidden(error):
            logger.warning(f"403 Forbidden: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Forbidden',
                'message': 'You do not have permission to access this resource'
            }, 403)
        
        # 404 Not Found
        @app.errorhandler(404)
        def not_found(error):
            logger.info(f"404 Not Found: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Not found',
                'message': 'The requested resource was not found'
            }, 404)
        
        # 405 Method Not Allowed
        @app.errorhandler(405)
        def method_not_allowed(error):
            logger.warning(f"405 Method Not Allowed: {request.method} {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Method not allowed',
                'message': f'The {request.method} method is not allowed for this endpoint'
            }, 405)
        
        # 413 Payload Too Large
        @app.errorhandler(413)
        def payload_too_large(error):
            logger.warning(f"413 Payload Too Large: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Payload too large',
                'message': 'Request body is too large'
            }, 413)
        
        # 415 Unsupported Media Type
        @app.errorhandler(415)
        def unsupported_media_type(error):
            logger.warning(f"415 Unsupported Media Type: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Unsupported media type',
                'message': 'Content-Type not supported. Use application/json'
            }, 415)
        
        # 429 Too Many Requests
        @app.errorhandler(429)
        def too_many_requests(error):
            logger.warning(f"429 Too Many Requests: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Too many requests',
                'message': 'Rate limit exceeded. Please slow down.'
            }, 429)
        
        # 500 Internal Server Error
        @app.errorhandler(500)
        def internal_error(error):
            logger.error(f"500 Internal Server Error: {request.path}")
            logger.error(traceback.format_exc())
            
            # Don't expose internal errors in production
            if app.config.get('DEBUG'):
                return response_middleware.create_cors_response({
                    'error': 'Internal server error',
                    'message': str(error),
                    'traceback': traceback.format_exc()
                }, 500)
            else:
                return response_middleware.create_cors_response({
                    'error': 'Internal server error',
                    'message': 'An unexpected error occurred'
                }, 500)
        
        # 502 Bad Gateway
        @app.errorhandler(502)
        def bad_gateway(error):
            logger.error(f"502 Bad Gateway: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Bad gateway',
                'message': 'Error communicating with upstream service'
            }, 502)
        
        # 503 Service Unavailable
        @app.errorhandler(503)
        def service_unavailable(error):
            logger.error(f"503 Service Unavailable: {request.path}")
            return response_middleware.create_cors_response({
                'error': 'Service unavailable',
                'message': 'Service temporarily unavailable. Please try again later.'
            }, 503)
        
        # Generic exception handler
        @app.errorhandler(Exception)
        def handle_unexpected_error(error):
            logger.error(f"Unexpected error: {str(error)}")
            logger.error(traceback.format_exc())
            
            # Log to external monitoring service (e.g., Sentry)
            ErrorHandler.log_to_monitoring_service(error)
            
            if app.config.get('DEBUG'):
                return response_middleware.create_cors_response({
                    'error': 'Unexpected error',
                    'message': str(error),
                    'type': type(error).__name__,
                    'traceback': traceback.format_exc()
                }, 500)
            else:
                return response_middleware.create_cors_response({
                    'error': 'An unexpected error occurred',
                    'message': 'Please contact support if this persists'
                }, 500)
    
    @staticmethod
    def log_to_monitoring_service(error):
        """Log error to external monitoring service (Sentry, etc.)"""
        try:
            # Add your error tracking service here
            # Example: sentry_sdk.capture_exception(error)
            pass
        except Exception as e:
            logger.error(f"Failed to log to monitoring service: {e}")


error_handler = ErrorHandler()