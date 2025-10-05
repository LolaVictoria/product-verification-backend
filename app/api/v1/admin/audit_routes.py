"""
Admin Audit Routes
Audit logs, activity tracking, and compliance reporting
"""
from flask import Blueprint, request
import logging

from app.services.admin.admin_service import admin_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware

audit_bp = Blueprint('admin_audit', __name__)
logger = logging.getLogger(__name__)


@audit_bp.route('/logs', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_audit_logs(current_user_id, current_user_role):
    """Get audit logs with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        action_type = request.args.get('action_type', 'all')
        user_id = request.args.get('user_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        result = admin_service.get_audit_logs(
            page=page,
            limit=limit,
            action_type=action_type,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get audit logs error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get audit logs'
        }, 500)


@audit_bp.route('/logs/<log_id>', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_audit_log_details(current_user_id, current_user_role, log_id):
    """Get detailed audit log entry"""
    try:
        result = admin_service.get_audit_log_details(log_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get audit log details error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get audit log details'
        }, 500)


@audit_bp.route('/activity', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_user_activity(current_user_id, current_user_role):
    """Get user activity summary"""
    try:
        user_id = request.args.get('user_id')
        time_range = request.args.get('time_range', '30d')
        
        if not user_id:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'user_id is required'
            }, 400)
        
        result = admin_service.get_user_activity(user_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get user activity error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get user activity'
        }, 500)


@audit_bp.route('/export', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
def export_audit_logs(current_user_id, current_user_role):
    """Export audit logs as CSV/JSON"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        export_format = data.get('format', 'csv')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        action_type = data.get('action_type', 'all')
        
        result = admin_service.export_audit_logs(
            export_format,
            start_date,
            end_date,
            action_type
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Export audit logs error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to export audit logs'
        }, 500)