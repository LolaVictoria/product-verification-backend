"""
Manufacturer Dashboard Routes
Overview stats, KPIs, and summary information
"""
from flask import Blueprint, request
import logging

from app.services.manufacturer.account_service import account_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.services.access_control_service import access_control_service

dashboard_bp = Blueprint('manufacturer_dashboard', __name__)
logger = logging.getLogger(__name__)


@dashboard_bp.route('/stats', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_dashboard_stats(current_user_id, current_user_role):
    """Get manufacturer dashboard statistics"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        time_range = request.args.get('time_range', '30d')
        
        result = account_service.get_dashboard_stats(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get dashboard stats'
        }, 500)


@dashboard_bp.route('/overview', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_manufacturer_overview(current_user_id, current_user_role):
    """Get manufacturer account overview"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        result = account_service.get_manufacturer_overview(manufacturer_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Manufacturer overview error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get overview'
        }, 500)


@dashboard_bp.route('/quick-stats', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_quick_stats(current_user_id, current_user_role):
    """Get quick stats for dashboard widgets"""
    try:
        access_check = access_control_service.validate_manufacturer_access(
            current_user_id, current_user_role
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        manufacturer_id = access_check['manufacturer_id']
        result = account_service.get_quick_stats(manufacturer_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Quick stats error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get quick stats'
        }, 500)