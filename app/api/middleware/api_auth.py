# middleware/api_auth.py
from functools import wraps
from flask import request, jsonify, g
from app.services.manufacturer.api_key_service import api_key_service
import logging

logger = logging.getLogger(__name__)

def require_api_key(f):
    """
    Decorator to validate API key for external manufacturer integrations
    Usage: @require_api_key above route functions
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from header
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            return jsonify({
                'error': 'API key required',
                'message': 'Please provide API key in X-API-Key header or Authorization header'
            }), 401
        
        try:
            # Validate API key and get manufacturer
            manufacturer = api_key_service.validate_api_key(api_key)
            
            if not manufacturer:
                return jsonify({
                    'error': 'Invalid API key',
                    'message': 'The provided API key is invalid or expired'
                }), 401
            
            if manufacturer.get('status') != 'active':
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'Your manufacturer account is not active. Please contact support.'
                }), 403
            
            # Store manufacturer info in Flask's g object for use in route
            g.current_manufacturer = manufacturer
            g.manufacturer_id = manufacturer['_id']
            
            # Log API usage for analytics/billing
            api_key_service.log_api_usage(manufacturer['_id'], request.endpoint)
            
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"API authentication error: {str(e)}")
            return jsonify({
                'error': 'Authentication failed',
                'message': 'Unable to authenticate API key'
            }), 500
    
    return decorated_function


def require_api_key_with_rate_limit(requests_per_minute=100):
    """
    Decorator with rate limiting based on subscription plan
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # First validate API key
            api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            
            try:
                manufacturer = api_key_service.validate_api_key(api_key)
                
                if not manufacturer:
                    return jsonify({'error': 'Invalid API key'}), 401
                
                # Check rate limits based on subscription plan
                if not api_key_service.check_rate_limit(manufacturer['_id'], requests_per_minute):
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'You have exceeded {requests_per_minute} requests per minute. Please upgrade your plan.'
                    }), 429
                
                g.current_manufacturer = manufacturer
                g.manufacturer_id = manufacturer['_id']
                
                # Log usage
                api_key_service.log_api_usage(manufacturer['_id'], request.endpoint)
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"API authentication error: {str(e)}")
                return jsonify({'error': 'Authentication failed'}), 500
        
        return decorated_function
    return decorator


def get_current_manufacturer():
    """Helper function to get current manufacturer from g object"""
    return getattr(g, 'current_manufacturer', None)


def get_manufacturer_id():
    """Helper function to get current manufacturer ID from g object"""
    return getattr(g, 'manufacturer_id', None)