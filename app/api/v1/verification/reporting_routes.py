"""
Verification Reporting Routes
Report counterfeits, suspicious activity, and view reports
"""
from flask import Blueprint, request
import logging

from app.services.verification.verification_service import verification_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.rate_limiting import rate_limit

reporting_bp = Blueprint('verification_reporting', __name__)
logger = logging.getLogger(__name__)


@reporting_bp.route('/counterfeit', methods=['POST'])
@auth_middleware.token_required_with_roles(['customer'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def report_counterfeit(current_user_id, current_user_role):
    """Report a counterfeit product (authenticated customers only)"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'error': 'Request body required'
            }, 400)
        
        # Validate required fields
        required_fields = ['serial_number', 'product_name', 'device_category']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return response_middleware.create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        # Create counterfeit report
        result = verification_service.create_counterfeit_report(
            customer_id=current_user_id,
            report_data=data
        )
        
        return response_middleware.create_cors_response({
            'status': 'success',
            'message': 'Counterfeit report submitted successfully',
            'report_id': result
        }, 201)
        
    except Exception as e:
        logger.error(f"Counterfeit report error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to submit report'
        }, 500)


@reporting_bp.route('/suspicious', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def report_suspicious_activity():
    """Report suspicious verification activity (public or authenticated)"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'error': 'Request body required'
            }, 400)
        
        # Optional authentication
        reporter_id = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                from app.services.auth.token_service import token_service
                token = auth_header.split(' ')[1]
                payload = token_service.verify_token(token)
                reporter_id = payload.get('sub') or payload.get('user_id')
            except:
                pass
        
        result = verification_service.report_suspicious_activity(data, reporter_id)
        
        return response_middleware.create_cors_response({
            'status': 'success',
            'message': 'Report submitted successfully'
        }, 200)
        
    except Exception as e:
        logger.error(f"Report suspicious activity error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to report suspicious activity'
        }, 500)


@reporting_bp.route('/reports', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def get_reports(current_user_id, current_user_role):
    """Get counterfeit reports (manufacturer/admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        status = request.args.get('status', 'all')
        
        result = verification_service.get_counterfeit_reports(
            current_user_id,
            current_user_role,
            page,
            limit,
            status
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get reports error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to get reports'
        }, 500)


@reporting_bp.route('/reports/<report_id>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin', 'customer'])
def get_report_details(current_user_id, current_user_role, report_id):
    """Get counterfeit report details"""
    try:
        result = verification_service.get_report_details(
            report_id,
            current_user_id,
            current_user_role
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get report details error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to get report details'
        }, 500)


@reporting_bp.route('/reports/<report_id>/resolve', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
def resolve_report(current_user_id, current_user_role, report_id):
    """Resolve a counterfeit report (manufacturer/admin only)"""
    try:
        data = request.get_json() or {}
        resolution_notes = data.get('notes', '')
        
        result = verification_service.resolve_counterfeit_report(
            report_id,
            current_user_id,
            resolution_notes
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Resolve report error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to resolve report'
        }, 500)


@reporting_bp.route('/my-reports', methods=['GET'])
@auth_middleware.token_required_with_roles(['customer'])
def get_my_reports(current_user_id, current_user_role):
    """Get reports submitted by current customer"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        result = verification_service.get_customer_reports(
            current_user_id,
            page,
            limit
        )
        
        return response_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Get my reports error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Failed to get reports'
        }, 500)