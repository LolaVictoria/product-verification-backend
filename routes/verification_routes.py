# routes/verification_routes.py
from flask import Blueprint, request
import logging

from services.verification_service import verification_service
from middleware.auth_middleware import auth_middleware
from middleware.rate_limiting import rate_limit

verification_bp = Blueprint('verification', __name__)
logger = logging.getLogger(__name__)

@verification_bp.route('/<serial_number>', methods=['GET'])
@rate_limit({'per_minute': 50, 'per_hour': 1000})
def verify_product(serial_number):
    """Public product verification endpoint"""
    try:
        customer_id = None
        user_role = None
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Try to extract user info if authenticated
        auth_header = request.headers.get('Authorization')
        if auth_header:
            # Optional authentication - don't fail if token is invalid
            from utils.validators import validate_token
            import os
            user_id, role, error, status = validate_token(auth_header, os.getenv('SECRET_KEY'))
            if not error:
                customer_id = str(user_id) if user_id else None
                user_role = role
        
        result = verification_service.verify_product(
            serial_number=serial_number,
            customer_id=customer_id,
            user_role=user_role,
            user_ip=user_ip
        )
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return auth_middleware.create_cors_response({
            'authentic': False,
            'error': 'Verification service error'
        }, 500)

@verification_bp.route('/batch', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 100})
def verify_batch():
    """Batch product verification"""
    try:
        data = request.get_json()
        serial_numbers = data.get('serial_numbers', [])
        
        if not serial_numbers or len(serial_numbers) > 10:
            return auth_middleware.create_cors_response({
                'error': 'Please provide 1-10 serial numbers'
            }, 400)
        
        customer_id = None
        user_role = None
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Try to extract user info if authenticated
        auth_header = request.headers.get('Authorization')
        if auth_header:
            from utils.validators import validate_token
            import os
            user_id, role, error, status = validate_token(auth_header, os.getenv('SECRET_KEY'))
            if not error:
                customer_id = str(user_id) if user_id else None
                user_role = role
        
        result = verification_service.verify_batch(
            serial_numbers=serial_numbers,
            customer_id=customer_id,
            user_role=user_role,
            user_ip=user_ip
        )
        
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Batch verification error: {e}")
        return auth_middleware.create_cors_response({
            'error': 'Batch verification failed'
        }, 500)

@verification_bp.route('/device-details/<serial_number>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'customer', 'admin'])
def get_device_details(current_user_id, current_user_role, serial_number):
    """Get detailed device information"""
    try:
        result = verification_service.get_device_details(serial_number)
        
        if result:
            return auth_middleware.create_cors_response({
                "status": "success",
                "data": result
            }, 200)
        else:
            return auth_middleware.create_cors_response({
                "status": "not_found",
                "error": "Device details not found"
            }, 404)
                
    except Exception as e:
        logger.error(f"Device details error: {e}")
        return auth_middleware.create_cors_response({"error": "Could not load device details"}, 500)

@verification_bp.route('/ownership-history/<serial_number>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'customer', 'admin'])
def get_ownership_history(current_user_id, current_user_role, serial_number):
    """Get ownership history for a verified product"""
    try:
        result = verification_service.get_ownership_history(serial_number)
        
        return auth_middleware.create_cors_response({
            "status": "success",
            "serial_number": serial_number,
            "history": result
        }, 200)

    except Exception as e:
        logger.error(f"Ownership history error: {e}")
        return auth_middleware.create_cors_response({"error": "Could not load ownership history"}, 500)

@verification_bp.route('/report-counterfeit', methods=['POST'])
@auth_middleware.token_required_with_roles(['customer'])
def report_counterfeit(current_user_id, current_user_role):
    """Report a counterfeit product"""
    try:
        data = request.get_json()
        
        required_fields = ['serial_number', 'product_name', 'device_category']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return auth_middleware.create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        result = verification_service.create_counterfeit_report(
            customer_id=current_user_id,
            report_data=data
        )
        
        return auth_middleware.create_cors_response({
            'status': 'success',
            'message': 'Counterfeit report submitted successfully',
            'report_id': result
        }, 201)
        
    except Exception as e:
        logger.error(f"Counterfeit report error: {e}")
        return auth_middleware.create_cors_response({'error': 'Failed to submit report'}, 500)

@verification_bp.route('/stats', methods=['GET'])
def get_verification_stats():
    """Get system verification statistics"""
    try:
        result = verification_service.get_system_stats()
        return auth_middleware.create_cors_response(result, 200)
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return auth_middleware.create_cors_response({
            "total_devices": 0,
            "blockchain_devices": 0,
            "total_verifications": 0,
            "authenticity_rate": 0
        }, 500)