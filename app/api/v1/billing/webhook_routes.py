"""
Billing Webhook Routes
Stripe webhook handlers for payment events
"""
from flask import Blueprint, request
import logging

from app.services.billing.stripe_service import stripe_service
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.webhook_middleware import webhook_middleware

billing_webhook_bp = Blueprint('billing_webhooks', __name__)
logger = logging.getLogger(__name__)


@billing_webhook_bp.route('/stripe', methods=['POST'])
@webhook_middleware.verify_stripe_signature
def handle_stripe_webhook():
    """Handle Stripe webhook events"""
    try:
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get('Stripe-Signature')
        
        result = stripe_service.handle_webhook(payload, sig_header)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Webhook processing failed'
        }, 400)


@billing_webhook_bp.route('/stripe/test', methods=['POST'])
@webhook_middleware.verify_stripe_signature
def test_stripe_webhook():
    """Test Stripe webhook endpoint"""
    try:
        return response_middleware.create_cors_response({
            'success': True,
            'message': 'Webhook endpoint is working'
        }, 200)
        
    except Exception as e:
        logger.error(f"Stripe webhook test error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Webhook test failed'
        }, 500)