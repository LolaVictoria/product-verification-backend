# routes/analytics_routes.py
from flask import Blueprint, request
import logging

from services.analytics_service import analytics_service
from middleware.auth_middleware import auth_middleware

analytics_bp = Blueprint('analytics', __name__)
logger = logging.getLogger(__name__)

@analytics_bp.route('/manufacturer/<manufacturer_id>/overview', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer', 'admin'])
def get_manufacturer_overview(current_user_id, current_user_role, manufacturer_id):
    """Get manufacturer analytics overview"""
    try:
        # Access control
        if current_user_role != 'admin' and current_user_id != manufacturer_id:
            return auth_middleware.create_cors_response({'error': 'Unauthorized'}, 403)
        
        time_range = request.args.get('timeRange', '30d')
        
        result = analytics_service.get_manufacturer_overview(manufacturer_id, time_range)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Manufacturer overview error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@analytics_bp.route('/manufacturer/<manufacturer_id>/verification-trends', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer', 'admin'])
def get_verification_trends(current_user_id, current_user_role, manufacturer_id):
    """Get daily verification trends"""
    try:
        # Access control
        if current_user_role != 'admin' and current_user_id != manufacturer_id:
            return auth_middleware.create_cors_response({'error': 'Unauthorized'}, 403)
        
        time_range = request.args.get('timeRange', '30d')
        
        result = analytics_service.get_verification_trends(manufacturer_id, time_range)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification trends error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@analytics_bp.route('/manufacturer/<manufacturer_id>/device-analytics', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer', 'admin'])
def get_device_analytics(current_user_id, current_user_role, manufacturer_id):
    """Get device analytics for manufacturer"""
    try:
        # Access control
        if current_user_role != 'admin' and current_user_id != manufacturer_id:
            return auth_middleware.create_cors_response({'error': 'Unauthorized'}, 403)
        
        time_range = request.args.get('timeRange', '30d')
        
        result = analytics_service.get_device_analytics(manufacturer_id, time_range)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Device analytics error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@analytics_bp.route('/manufacturer/<manufacturer_id>/verification-logs', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer', 'admin'])
def get_verification_logs(current_user_id, current_user_role, manufacturer_id):
    """Get manufacturer's verification logs"""
    try:
        # Access control
        if current_user_role != 'admin' and current_user_id != manufacturer_id:
            return auth_middleware.create_cors_response({'error': 'Unauthorized'}, 403)
        
        limit = int(request.args.get('limit', 50))
        time_range = request.args.get('timeRange', '30d')
        
        result = analytics_service.get_verification_logs(manufacturer_id, limit, time_range)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification logs error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@analytics_bp.route('/customer/<customer_id>/overview', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['customer', 'admin'])
def get_customer_overview(current_user_id, current_user_role, customer_id):
    """Get customer's personal analytics overview"""
    try:
        # Access control
        if current_user_role != 'admin' and current_user_id != customer_id:
            return auth_middleware.create_cors_response({'error': 'Unauthorized'}, 403)
        
        time_range = request.args.get('timeRange', '30d')
        
        result = analytics_service.get_customer_analytics(customer_id, time_range)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Customer analytics error: {e}")
        return auth_middleware.create_cors_response({'error': 'Internal server error'}, 500)

@analytics_bp.route('/record-verification', methods=['POST'])
def record_verification():
    """Record verification attempt for analytics"""
    try:
        data = request.get_json()
        
        result = analytics_service.record_verification_attempt(data)
        
        return auth_middleware.create_cors_response({
            'success': True,
            'verification_id': result
        }, 200)
        
    except Exception as e:
        logger.error(f"Record verification error: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to record verification'}, 500)