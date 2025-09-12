from flask import Blueprint, request, jsonify, make_response
from datetime import datetime, timezone
from bson import ObjectId
import traceback
from services.verification_service import VerificationService
from middleware.auth_middleware import AuthMiddleware
from utils.formatters import create_cors_response
from utils.helper_functions import get_db_connection, log_verification_attempt

def create_verification_routes(app):
    """Create and configure verification routes blueprint"""
    verification_bp = Blueprint('verification', __name__)

    @verification_bp.route('/verify/<serial_number>', methods=['GET'])
    @AuthMiddleware.token_required(['manufacturer', 'customer'])
    def verify_product(current_user_id, current_user_role, serial_number):
        """Enhanced verification endpoint with device info and customer tracking"""
        try:
            verification_service = VerificationService()
            user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            # Perform verification
            result = verification_service.verify_product(
                serial_number=serial_number,
                customer_id=current_user_id,
                user_role=current_user_role,
                user_ip=user_ip
            )
            
            return create_cors_response(result, 200)
            
        except Exception as e:
            print(f"Verification route error: {e}")
            traceback.print_exc()
            return create_cors_response({
                "authentic": False, 
                "message": "Verification service error",
                "error": str(e)
            }, 500)

    @verification_bp.route('/verify-batch', methods=['POST'])
    @AuthMiddleware.token_required(['manufacturer', 'customer'])
    def verify_batch(current_user_id, current_user_role):
        """Enhanced public batch verification endpoint"""
        try:
            data = request.get_json()
            serial_numbers = data.get('serialNumbers', [])
            
            if not serial_numbers or len(serial_numbers) > 10:
                return create_cors_response({
                    "error": "Please provide 1-10 serial numbers"
                }, 400)
            
            verification_service = VerificationService()
            user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            results = []
            total_verified = 0
            
            for serial_number in serial_numbers:
                result = verification_service.verify_product(
                    serial_number=serial_number,
                    customer_id=current_user_id,
                    user_role=current_user_role,
                    user_ip=user_ip
                )
                
                if result.get("authentic"):
                    total_verified += 1
                    
                results.append({
                    "serialNumber": serial_number,
                    "authentic": result.get("authentic", False),
                    "brand": result.get("brand"),
                    "model": result.get("model"),
                    "deviceType": result.get("deviceType"),
                    "manufacturerName": result.get("manufacturerName"),
                    "source": result.get("source"),
                    "message": result.get("message", "")
                })
            
            return create_cors_response({
                "status": "success",
                "results": results,
                "total_verified": total_verified,
                "total_checked": len(results)
            }, 200)
            
        except Exception as e:
            print(f"Batch verification error: {e}")
            return create_cors_response({"error": "Batch verification failed"}, 500)

    @verification_bp.route('/device-details/<serial_number>', methods=['GET'])
    @AuthMiddleware.token_required(['manufacturer', 'customer'])
    def get_device_details(current_user_id, current_user_role, serial_number):
        """Get detailed device information"""
        try:
            verification_service = VerificationService()
            details = verification_service.get_device_details(serial_number)
            
            if details:
                return create_cors_response({
                    "status": "success",
                    **details
                }, 200)
            else:
                return create_cors_response({
                    "status": "not_found",
                    "error": "Device details not found"
                }, 404)
                
        except Exception as e:
            print(f"Device details error: {e}")
            return create_cors_response({"error": "Could not load device details"}, 500)

    @verification_bp.route('/ownership-history/<serial_number>', methods=['GET'])
    @AuthMiddleware.token_required(['manufacturer', 'customer'])
    def get_ownership_history(current_user_id, current_user_role, serial_number):
        """Get ownership history for a verified product"""
        try:
            verification_service = VerificationService()
            history = verification_service.get_ownership_history(serial_number)
            
            return create_cors_response({
                "status": "success",
                "serial_number": serial_number,
                "history": history
            }, 200)

        except Exception as e:
            print(f"Ownership history error: {e}")
            return create_cors_response({"error": "Could not load ownership history"}, 500)

    @verification_bp.route('/stats', methods=['GET'])
    def get_verification_stats():
        """Get system verification statistics"""
        try:
            verification_service = VerificationService()
            stats = verification_service.get_system_stats()
            
            return create_cors_response(stats, 200)
            
        except Exception as e:
            print(f"Stats error: {e}")
            return create_cors_response({
                "total_devices": 0,
                "blockchain_devices": 0,
                "total_verifications": 0,
                "authenticity_rate": 0
            }, 500)

    @verification_bp.route('/log-verification', methods=['POST'])
    def log_verification():
        """Log verification attempts for analytics"""
        try:
            data = request.get_json()
            
            log_entry = {
                "serial_number": data.get("serial_number"),
                "authentic": data.get("authentic", False),
                "timestamp": datetime.now(timezone.utc),
                "user_ip": request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                "user_agent": data.get("user_agent", "")
            }
            
            db = get_db_connection()
            db.verifications.insert_one(log_entry)
            
            return create_cors_response({"status": "logged"}, 200)
            
        except Exception as e:
            print(f"Verification logging error: {e}")
            return create_cors_response({"error": "Logging failed"}, 500)

    @verification_bp.route('/report-counterfeit', methods=['POST'])
    @AuthMiddleware.token_required(['customer'])
    def report_counterfeit(current_user_id, current_user_role):
        """Report a counterfeit product"""
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['serial_number', 'product_name', 'purchase_date']
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return create_cors_response({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }, 400)
            
            verification_service = VerificationService()
            report_id = verification_service.create_counterfeit_report(
                customer_id=current_user_id,
                report_data=data
            )
            
            return create_cors_response({
                'status': 'success',
                'message': 'Counterfeit report submitted successfully',
                'report_id': report_id
            }, 201)
            
        except Exception as e:
            print(f"Counterfeit report error: {e}")
            return create_cors_response({'error': 'Failed to submit report'}, 500)

    return verification_bp