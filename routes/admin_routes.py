# routes/admin_routes.py
from flask import Blueprint, request
from datetime import datetime, timezone
import logging
from bson import ObjectId

from services.admin_service import admin_service
from middleware.auth_middleware import auth_middleware

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)

@admin_bp.route('/manufacturers', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def list_all_manufacturers(current_user_id, current_user_role):
    """List all manufacturers (admin only)"""
    try:
        result = admin_service.list_all_manufacturers()
        
        return auth_middleware.create_cors_response({
            'manufacturers': result['manufacturers'],
            'total': result['total']
        }, 200)
        
    except Exception as e:
        logger.error(f"Error listing manufacturers: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to list manufacturers'}, 500)

@admin_bp.route('/manufacturers/<manufacturer_id>/stats', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def get_manufacturer_stats(current_user_id, current_user_role, manufacturer_id):
    """Get detailed manufacturer statistics (admin only)"""
    try:
        result = admin_service.get_manufacturer_admin_stats(manufacturer_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response(result['data'], 200)
        
    except Exception as e:
        logger.error(f"Error getting manufacturer stats: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to get admin stats'}, 500)

@admin_bp.route('/system/health', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def system_health(current_user_id, current_user_role):
    """Get system health information (admin only)"""
    try:
        result = admin_service.get_system_health()
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to get system health'}, 500)

@admin_bp.route('/counterfeit-reports', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def get_all_counterfeit_reports(current_user_id, current_user_role):
    """Get all counterfeit reports (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        status = request.args.get('status')
        
        result = admin_service.get_all_counterfeit_reports(page, limit, status)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Error getting counterfeit reports: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to get counterfeit reports'}, 500)

@admin_bp.route('/manufacturers/<manufacturer_id>/verify', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def verify_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Verify manufacturer account (admin only)"""
    try:
        result = admin_service.verify_manufacturer(manufacturer_id, current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Error verifying manufacturer: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to verify manufacturer'}, 500)

@admin_bp.route('/manufacturers/<manufacturer_id>/revoke', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def revoke_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Revoke manufacturer verification"""
    try:
        result = admin_service.revoke_manufacturer_verification(manufacturer_id, current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Error revoking manufacturer: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to revoke manufacturer'}, 500)

@admin_bp.route('/manufacturers/<manufacturer_id>/suspend', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def suspend_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Suspend manufacturer account"""
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')
        
        result = admin_service.suspend_manufacturer(manufacturer_id, current_user_id, reason)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Error suspending manufacturer: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to suspend manufacturer'}, 500)

@admin_bp.route('/manufacturers/<manufacturer_id>/activate', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def activate_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Activate suspended manufacturer account"""
    try:
        result = admin_service.activate_manufacturer(manufacturer_id, current_user_id)
        
        if not result['success']:
            return auth_middleware.create_cors_response({'error': result['message']}, 404)
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': result['message']
        }, 200)
        
    except Exception as e:
        logger.error(f"Error activating manufacturer: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to activate manufacturer'}, 500)

@admin_bp.route('/analytics', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def get_analytics(current_user_id, current_user_role):
    """Get system analytics"""
    try:
        time_period = request.args.get('period', '7d')
        result = admin_service.get_system_analytics(time_period)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to get analytics'}, 500)

@admin_bp.route('/audit-logs', methods=['GET'])
@auth_middleware.token_required_with_roles(allowed_roles=['admin'])
def get_audit_logs(current_user_id, current_user_role):
    """Get audit logs"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        action_type = request.args.get('action_type')
        user_id = request.args.get('user_id')
        
        result = admin_service.get_audit_logs(page, limit, action_type, user_id)
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to get audit logs'}, 500)