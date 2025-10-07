"""
Admin Manufacturer Management Routes
Manage manufacturers, approve registrations, view/edit accounts
"""
from flask import Blueprint, request
import logging

from app.services.admin.admin_service import admin_service
from app.validators.manufacturer_validator import ManufacturerValidator
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware

admin_manufacturer_bp = Blueprint('admin_manufacturers', __name__)
logger = logging.getLogger(__name__)


@admin_manufacturer_bp.route('/manufacturers/', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_all_manufacturers(current_user_id, current_user_role):
    """Get all manufacturers with pagination and filters"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        status = request.args.get('status', 'all')
        search = request.args.get('search', '')
        sort_by = request.args.get('sort_by', 'created_at')
        
        result = admin_service.get_all_manufacturers(
            page=page,
            limit=limit,
            status=status,
            search=search,
            sort_by=sort_by
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get manufacturers error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get manufacturers'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_manufacturer_details(current_user_id, current_user_role, manufacturer_id):
    """Get detailed manufacturer information"""
    try:
        result = admin_service.get_manufacturer_details(manufacturer_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get manufacturer details error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get manufacturer details'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>/approve', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
def approve_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Approve pending manufacturer registration"""
    try:
        result = admin_service.approve_manufacturer(manufacturer_id, current_user_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Approve manufacturer error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to approve manufacturer'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>/reject', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
def reject_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Reject manufacturer registration"""
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided') if data else 'No reason provided'
        
        result = admin_service.reject_manufacturer(
            manufacturer_id, 
            current_user_id, 
            reason
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Reject manufacturer error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to reject manufacturer'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>/suspend', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
def suspend_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Suspend manufacturer account"""
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided') if data else 'No reason provided'
        
        result = admin_service.suspend_manufacturer(
            manufacturer_id, 
            current_user_id, 
            reason
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Suspend manufacturer error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to suspend manufacturer'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>/reactivate', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
def reactivate_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Reactivate suspended manufacturer"""
    try:
        result = admin_service.reactivate_manufacturer(manufacturer_id, current_user_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Reactivate manufacturer error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to reactivate manufacturer'
        }, 500)


@admin_manufacturer_bp.route('/<manufacturer_id>', methods=['PUT'])
@auth_middleware.token_required_with_roles(['admin'])
def update_manufacturer(current_user_id, current_user_role, manufacturer_id):
    """Update manufacturer information"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        result = admin_service.update_manufacturer(manufacturer_id, data, current_user_id)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Update manufacturer error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to update manufacturer'
        }, 500)



@admin_manufacturer_bp.route('/<manufacturer_id>/analytics', methods=['GET'])
@auth_middleware.token_required_with_roles(['admin'])
def get_manufacturer_analytics(current_user_id, current_user_role, manufacturer_id):
    """Get manufacturer analytics (admin view)"""
    try:
        time_range = request.args.get('time_range', '30d')
        result = admin_service.get_manufacturer_analytics(manufacturer_id, time_range)
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get manufacturer analytics error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get analytics'
        }, 500)