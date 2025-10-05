"""
Billing Subscription Routes
Subscription management, upgrades, cancellations, and portal access
"""
from flask import Blueprint, request
import logging

from app.services.billing.subscription_service import subscription_service
from app.services.billing.stripe_service import stripe_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware

subscription_bp = Blueprint('subscription', __name__)
logger = logging.getLogger(__name__)


@subscription_bp.route('/status', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_subscription_status(current_user_id, current_user_role):
    """Get current subscription status"""
    try:
        result = subscription_service.get_subscription_status(current_user_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get subscription error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get subscription'
        }, 500)


@subscription_bp.route('/upgrade', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def upgrade_subscription(current_user_id, current_user_role):
    """Upgrade to higher plan"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        new_plan = data.get('plan')
        
        if not new_plan:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Plan is required'
            }, 400)
        
        result = subscription_service.upgrade_subscription(current_user_id, new_plan)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Upgrade subscription error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to upgrade subscription'
        }, 500)


@subscription_bp.route('/downgrade', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def downgrade_subscription(current_user_id, current_user_role):
    """Downgrade to lower plan"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        new_plan = data.get('plan')
        
        if not new_plan:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Plan is required'
            }, 400)
        
        result = subscription_service.downgrade_subscription(current_user_id, new_plan)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Downgrade subscription error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to downgrade subscription'
        }, 500)


@subscription_bp.route('/cancel', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def cancel_subscription(current_user_id, current_user_role):
    """Cancel subscription"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'No reason provided')
        
        result = subscription_service.cancel_subscription(current_user_id, reason)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Cancel subscription error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to cancel subscription'
        }, 500)


@subscription_bp.route('/portal', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def create_portal_session(current_user_id, current_user_role):
    """Create Stripe customer portal session"""
    try:
        # Get manufacturer's Stripe customer ID
        subscription = subscription_service.get_subscription_status(current_user_id)
        
        if not subscription.get('success'):
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'No subscription found'
            }, 404)
        
        stripe_customer_id = subscription.get('subscription', {}).get('stripe_customer_id')
        
        if not stripe_customer_id:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'No Stripe customer found'
            }, 404)
        
        return_url = request.headers.get('Referer', '/dashboard/billing')
        result = stripe_service.create_portal_session(stripe_customer_id, return_url)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Portal session error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to create portal session'
        }, 500)


@subscription_bp.route('/usage', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_usage_stats(current_user_id, current_user_role):
    """Get current usage statistics"""
    try:
        time_period = request.args.get('period', '30d')
        result = subscription_service.get_usage_statistics(current_user_id, time_period)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Usage stats error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get usage statistics'
        }, 500)


@subscription_bp.route('/plans', methods=['GET'])
def get_available_plans():
    """Get available subscription plans (public endpoint)"""
    try:
        result = subscription_service.get_available_plans()
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get plans error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get plans'
        }, 500)


@subscription_bp.route('/history', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_subscription_history(current_user_id, current_user_role):
    """Get subscription change history"""
    try:
        result = subscription_service.get_subscription_history(current_user_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Subscription history error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get subscription history'
        }, 500)


@subscription_bp.route('/invoices', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_invoices(current_user_id, current_user_role):
    """Get billing invoices"""
    try:
        limit = request.args.get('limit', 10, type=int)
        result = subscription_service.get_invoices(current_user_id, limit)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get invoices error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get invoices'
        }, 500)