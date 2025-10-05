"""
Webhook Middleware
Middleware for webhook signature verification
"""
import logging
from functools import wraps
from flask import request
import os

from app.validators.webhook_validator import webhook_validator

logger = logging.getLogger(__name__)


class WebhookMiddleware:
    """Middleware for webhook handling"""
    
    @staticmethod
    def verify_stripe_signature(f):
        """Decorator to verify Stripe webhook signatures"""
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                payload = request.get_data()
                signature = request.headers.get('Stripe-Signature')
                secret = os.getenv('STRIPE_WEBHOOK_SECRET')
                
                if not webhook_validator.verify_stripe_signature(payload, signature, secret):
                    logger.warning("Invalid Stripe webhook signature")
                    return {'success': False, 'error': 'Invalid signature'}, 401
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Stripe webhook verification error: {e}")
                return {'success': False, 'error': 'Signature verification failed'}, 401
        
        return wrapper
    
    @staticmethod
    def verify_webhook_signature(secret_env_var):
        """
        Generic webhook signature verification decorator
        
        Args:
            secret_env_var: Name of environment variable containing webhook secret
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                try:
                    payload = request.get_data()
                    signature = request.headers.get('X-Webhook-Signature')
                    secret = os.getenv(secret_env_var)
                    
                    if not webhook_validator.verify_signature(payload, signature, secret):
                        logger.warning(f"Invalid webhook signature for {secret_env_var}")
                        return {'success': False, 'error': 'Invalid signature'}, 401
                    
                    return f(*args, **kwargs)
                    
                except Exception as e:
                    logger.error(f"Webhook verification error: {e}")
                    return {'success': False, 'error': 'Signature verification failed'}, 401
            
            return wrapper
        return decorator
    
    @staticmethod
    def validate_blockchain_event(data):
        """Validate blockchain event (proxy to validator)"""
        return webhook_validator.validate_blockchain_event(data)
    
    @staticmethod
    def validate_verification_event(data):
        """Validate verification event (proxy to validator)"""
        return webhook_validator.validate_verification_event(data)


webhook_middleware = WebhookMiddleware()