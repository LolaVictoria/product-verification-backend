"""
Admin System Routes
System health, monitoring, and configuration
"""
from flask import Blueprint, request
import logging

from app.services.admin.admin_service import admin_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware

system_bp = Blueprint('admin_system', __name__)
logger = logging.getLogger(__name__)


@system_bp.route('/health', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_system_health(current_user_id, current_user_role):
    """Get system health status"""
    try:
        result = admin_service.get_system_health()
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"System health error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get system health'
        }, 500)


@system_bp.route('/stats', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_system_stats(current_user_id, current_user_role):
    """Get system-wide statistics"""
    try:
        time_range = request.args.get('time_range', '30d')
        result = admin_service.get_system_stats(time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"System stats error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get system stats'
        }, 500)


@system_bp.route('/metrics', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_system_metrics(current_user_id, current_user_role):
    """Get real-time system metrics"""
    try:
        result = admin_service.get_system_metrics()
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"System metrics error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get system metrics'
        }, 500)


@system_bp.route('/database/status', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_database_status(current_user_id, current_user_role):
    """Get database connection status"""
    try:
        result = admin_service.get_database_status()
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Database status error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get database status'
        }, 500)


@system_bp.route('/config', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_system_config(current_user_id, current_user_role):
    """Get system configuration (non-sensitive)"""
    try:
        result = admin_service.get_system_config()
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"System config error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get system config'
        }, 500)