"""
Public Verification Routes
Product verification endpoints - public and authenticated access
"""
from flask import Blueprint, request
import logging

from app.services.verification.verification_service import verification_service
from app.utils.input_validators import validate_serial_number
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.rate_limiting import rate_limit

public_verification_bp = Blueprint('public_verification', __name__)
logger = logging.getLogger(__name__)


@public_verification_bp.route('/<serial_number>', methods=['GET'])
@rate_limit({'per_minute': 50, 'per_hour': 1000})
def verify_product(serial_number):
    """
    Public product verification endpoint
    No authentication required - anyone can verify products
    """
    try:
        # Validate serial number format
        try:
            clean_serial = validate_serial_number(serial_number)
        except ValueError as e:
            return response_middleware.create_error_response(str(e), 400)
        
        # Extract optional user info if authenticated
        customer_id = None
        user_role = None
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Try to extract auth info (optional - don't fail if invalid)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                from app.services.auth.token_service import token_service
                token = auth_header.split(' ')[1]
                payload = token_service.verify_token(token)
                
                customer_id = payload.get('sub') or payload.get('user_id')
                user_role = payload.get('role')
            except:
                # Invalid token - continue as anonymous
                pass
        
        # Perform verification
        result = verification_service.verify_product(
            serial_number=clean_serial,
            customer_id=customer_id,
            user_role=user_role,
            user_ip=user_ip
        )
        
        return response_middleware.create_success_response(result, 200)
        
    except Exception as e:
        logger.error(f"Verification error for {serial_number}: {e}")
        return response_middleware.create_cors_response({
            'error': 'Verification failed'
        }, 500)


@public_verification_bp.route('/batch', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 100})
def verify_batch():
    """
    Batch product verification
    Verify multiple products in one request (max 10)
    """
    try:
        data = request.get_json()
        
        if not data or 'serial_numbers' not in data:
            return response_middleware.create_cors_response({
                'error': 'serial_numbers array required'
            }, 400)
        
        serial_numbers = data['serial_numbers']
        
        if not isinstance(serial_numbers, list):
            return response_middleware.create_cors_response({
                'error': 'serial_numbers must be an array'
            }, 400)
        
        if len(serial_numbers) == 0:
            return response_middleware.create_cors_response({
                'error': 'At least one serial number required'
            }, 400)
        
        if len(serial_numbers) > 10:
            return response_middleware.create_cors_response({
                'error': 'Please provide 1-10 serial numbers'
            }, 400)
        
        # Validate each serial number
        try:
            clean_serials = [validate_serial_number(sn) for sn in serial_numbers]
        except ValueError as e:
            return response_middleware.create_error_response(
                f'Invalid serial number: {str(e)}', 
                400
            )
        
        # Extract optional user info
        customer_id = None
        user_role = None
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                from app.services.auth.token_service import token_service
                token = auth_header.split(' ')[1]
                payload = token_service.verify_token(token)
                
                customer_id = payload.get('sub') or payload.get('user_id')
                user_role = payload.get('role')
            except:
                pass
        
        # Batch verify
        result = verification_service.verify_batch(
            serial_numbers=clean_serials,
            customer_id=customer_id,
            user_role=user_role,
            user_ip=user_ip
        )
        
        return response_middleware.create_success_response(result, 200)
        
    except Exception as e:
        logger.error(f"Batch verification error: {e}")
        return response_middleware.create_cors_response({
            'error': 'Batch verification failed'
        }, 500)


@public_verification_bp.route('/device-details/<serial_number>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'customer', 'admin'])
def get_device_details(current_user_id, current_user_role, serial_number):
    """Get detailed device information (authenticated)"""
    try:
        result = verification_service.get_device_details(serial_number)
        
        if result:
            return response_middleware.create_cors_response({
                "status": "success",
                "data": result
            }, 200)
        else:
            return response_middleware.create_cors_response({
                "status": "not_found",
                "error": "Device details not found"
            }, 404)
                
    except Exception as e:
        logger.error(f"Device details error: {e}")
        return response_middleware.create_cors_response({
            "error": "Could not load device details"
        }, 500)


@public_verification_bp.route('/ownership-history/<serial_number>', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer', 'customer', 'admin'])
def get_ownership_history(current_user_id, current_user_role, serial_number):
    """Get ownership history for a verified product (authenticated)"""
    try:
        result = verification_service.get_ownership_history(serial_number)
        
        return response_middleware.create_cors_response({
            "status": "success",
            "serial_number": serial_number,
            "history": result
        }, 200)

    except Exception as e:
        logger.error(f"Ownership history error: {e}")
        return response_middleware.create_cors_response({
            "error": "Could not load ownership history"
        }, 500)


@public_verification_bp.route('/qr/<qr_code>', methods=['GET'])
@rate_limit({'per_minute': 50, 'per_hour': 1000})
def verify_by_qr(qr_code):
    """Verify product by QR code (public)"""
    try:
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        result = verification_service.verify_by_qr_code(qr_code, user_ip)
        
        return response_middleware.create_success_response(result, 200)
        
    except Exception as e:
        logger.error(f"QR verification error: {e}")
        return response_middleware.create_cors_response({
            'error': 'QR verification failed'
        }, 500)