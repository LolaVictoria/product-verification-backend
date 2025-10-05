"""
Manufacturer Analytics Routes
Analytics data, trends, verification logs, and reporting
"""
from flask import Blueprint, request
import logging

from app.services.manufacturer.analytics_service import analytics_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.services.access_control_service import access_control_service

analytics_bp = Blueprint('manufacturer_analytics', __name__)
logger = logging.getLogger(__name__)


@analytics_bp.route('/overview', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_analytics_overview(current_user_id, current_user_role):
    """Get analytics overview"""
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
        
        result = analytics_service.get_manufacturer_overview(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Analytics overview error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get analytics'
        }, 500)


@analytics_bp.route('/verification-trends', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_verification_trends(current_user_id, current_user_role):
    """Get daily verification trends"""
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
        
        result = analytics_service.get_verification_trends(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification trends error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get trends'
        }, 500)


@analytics_bp.route('/device-analytics', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_device_analytics(current_user_id, current_user_role):
    """Get device analytics (platform, browser breakdown)"""
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
        
        result = analytics_service.get_device_analytics(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Device analytics error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get device analytics'
        }, 500)


@analytics_bp.route('/geographic-distribution', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_geographic_distribution(current_user_id, current_user_role):
    """Get geographic distribution of verifications"""
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
        
        result = analytics_service.get_geographic_distribution(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Geographic distribution error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get geographic distribution'
        }, 500)


@analytics_bp.route('/verification-logs', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_verification_logs(current_user_id, current_user_role):
    """Get detailed verification logs"""
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
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        time_range = request.args.get('time_range', '30d')
        
        result = analytics_service.get_verification_logs(
            manufacturer_id, 
            page=page, 
            limit=limit, 
            time_range=time_range
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification logs error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get verification logs'
        }, 500)


@analytics_bp.route('/product/<product_id>/analytics', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_product_analytics(current_user_id, current_user_role, product_id):
    """Get analytics for a specific product"""
    try:
        access_check = access_control_service.can_access_product(
            current_user_id, current_user_role, product_id
        )
        
        if not access_check['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': access_check['message']
            }, 403)
        
        time_range = request.args.get('time_range', '30d')
        result = analytics_service.get_product_analytics(product_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Product analytics error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get product analytics'
        }, 500)


@analytics_bp.route('/export', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def export_analytics(current_user_id, current_user_role):
    """Export analytics data as CSV/JSON"""
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
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        export_format = data.get('format', 'csv')
        time_range = data.get('time_range', '30d')
        data_type = data.get('data_type', 'overview')
        
        result = analytics_service.export_analytics(
            manufacturer_id, 
            export_format, 
            time_range, 
            data_type
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Export analytics error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to export analytics'
        }, 500)