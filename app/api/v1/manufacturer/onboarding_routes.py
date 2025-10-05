"""
Manufacturer Onboarding Routes
Handles post-registration onboarding flow
"""
from flask import Blueprint, request
import logging

from app.services.onboarding_service import onboarding_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware

onboarding_bp = Blueprint('onboarding', __name__)
logger = logging.getLogger(__name__)

@onboarding_bp.route('/progress', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_onboarding_progress(current_user_id, current_user_role):
    """Get manufacturer's onboarding progress"""
    try:
        result = onboarding_service.get_onboarding_progress(current_user_id)
        return response_middleware.create_cors_response(result, 200)
    except Exception as e:
        logger.error(f"Onboarding progress error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to get onboarding progress'
        }, 500)

@onboarding_bp.route('/complete-step', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def complete_step(current_user_id, current_user_role):
    """Mark an onboarding step as completed"""
    try:
        data = request.get_json()
        step = data.get('step')
        
        if not step:
            return response_middleware.create_cors_response({
                'error': 'Step is required'
            }, 400)
        
        result = onboarding_service.mark_onboarding_step_completed(current_user_id, step)
        return response_middleware.create_cors_response(result, 200)
    except Exception as e:
        logger.error(f"Complete step error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to complete onboarding step'
        }, 500)