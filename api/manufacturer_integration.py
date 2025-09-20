# api/manufacturer_integration.py
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from services.analytics_service import AnalyticsService
from services.verification_service import VerificationService
from services.manufacturer_service import ManufacturerService
from middleware.auth_middleware import api_key_required, validate_manufacturer_access
# from utils.formatters import create_cors_response
from utils.validators import validate_integration_request
import hashlib
import hmac
import json

# Create blueprint for manufacturer integration
manufacturer_integration_bp = Blueprint('manufacturer_integration', __name__, url_prefix='/api/v1/integration')

# Initialize services
analytics_service = AnalyticsService()
verification_service = VerificationService()
manufacturer_service = ManufacturerService()

# ===============================
# MANUFACTURER ACCOUNT MANAGEMENT
# ===============================
@manufacturer_integration_bp.route('/manufacturer/create-account', methods=['POST'])
def create_manufacturer_account():
    """
    Create a manufacturer account for integration
    
    Expected payload:
    {
        "company_name": "Tech Corp Ltd",
        "primary_email": "admin@techcorp.com",
        "wallet_address": "0x123...",
        "contact_person": "John Doe",
        "phone_number": "+1234567890",
        "integration_callback_url": "https://techcorp.com/webhook",
        "api_permissions": ["verify", "analytics", "logs"]
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['company_name', 'primary_email', 'wallet_address', 'contact_person']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        # Create manufacturer account
        account_data = manufacturer_service.create_integration_account(data)
        
        return create_cors_response({
            'status': 'success',
            'message': 'Manufacturer account created successfully',
            'account_id': account_data['account_id'],
            'api_key': account_data['api_key'],
            'webhook_secret': account_data['webhook_secret'],
            'setup_instructions': {
                'step1': 'Store your API key securely',
                'step2': 'Configure webhook endpoint with provided secret',
                'step3': 'Test integration with /test-connection endpoint',
                'step4': 'Contact support for account verification'
            }
        }, 201)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

@manufacturer_integration_bp.route('/manufacturer/test-connection', methods=['GET'])
@api_key_required
def test_connection():
    """Test API connection and authentication"""
    try:
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        
        return create_cors_response({
            'status': 'success',
            'message': 'Connection successful',
            'manufacturer_id': str(manufacturer_data['_id']),
            'company_name': manufacturer_data['company_name'],
            'permissions': manufacturer_data.get('api_permissions', []),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# PRODUCT VERIFICATION API
# ===============================

@manufacturer_integration_bp.route('/verify/single', methods=['POST'])
@api_key_required
@validate_manufacturer_access(['verify'])
def verify_single_product():
    """
    Verify a single product
    
    Expected payload:
    {
        "serial_number": "ABC123",
        "customer_info": {
            "customer_id": "optional_customer_id",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0..."
        }
    }
    """
    try:
        data = request.get_json()
        serial_number = data.get('serial_number')
        customer_info = data.get('customer_info', {})
        
        if not serial_number:
            return create_cors_response({'error': 'serial_number is required'}, 400)
        
        # Get manufacturer info from API key
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        
        # Perform verification
        result = verification_service.verify_product(
            serial_number=serial_number,
            customer_id=customer_info.get('customer_id'),
            user_role='manufacturer_api',
            user_ip=customer_info.get('ip_address', request.remote_addr)
        )
        
        # Add integration-specific fields
        result['integration'] = {
            'api_version': 'v1',
            'manufacturer_id': str(manufacturer_data['_id']),
            'request_id': str(ObjectId()),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

@manufacturer_integration_bp.route('/verify/batch', methods=['POST'])
@api_key_required
@validate_manufacturer_access(['verify'])
def verify_batch_products():
    """
    Verify multiple products in batch
    
    Expected payload:
    {
        "serial_numbers": ["ABC123", "DEF456", "GHI789"],
        "customer_info": {
            "customer_id": "optional_customer_id",
            "ip_address": "192.168.1.1"
        }
    }
    """
    try:
        data = request.get_json()
        serial_numbers = data.get('serial_numbers', [])
        customer_info = data.get('customer_info', {})
        
        if not serial_numbers:
            return create_cors_response({'error': 'serial_numbers array is required'}, 400)
        
        if len(serial_numbers) > 10:
            return create_cors_response({'error': 'Maximum 10 serial numbers allowed per batch'}, 400)
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        
        # Perform batch verification
        result = verification_service.verify_batch(
            serial_numbers=serial_numbers,
            customer_id=customer_info.get('customer_id'),
            user_role='manufacturer_api',
            user_ip=customer_info.get('ip_address', request.remote_addr)
        )
        
        # Add integration metadata
        result['integration'] = {
            'api_version': 'v1',
            'manufacturer_id': str(manufacturer_data['_id']),
            'request_id': str(ObjectId()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'batch_size': len(serial_numbers)
        }
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# ANALYTICS API
# ===============================

@manufacturer_integration_bp.route('/analytics/overview', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['analytics'])
def get_analytics_overview():
    """Get manufacturer analytics overview"""
    try:
        time_range = request.args.get('time_range', '30d')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get analytics data
        overview = analytics_service.get_manufacturer_overview(manufacturer_id, time_range)
        
        # Add integration metadata
        overview['integration'] = {
            'api_version': 'v1',
            'manufacturer_id': manufacturer_id,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        return create_cors_response(overview, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

@manufacturer_integration_bp.route('/analytics/verification-trends', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['analytics'])
def get_verification_trends():
    """Get verification trends data"""
    try:
        time_range = request.args.get('time_range', '30d')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get trends data
        trends = analytics_service.get_verification_trends(manufacturer_id, time_range)
        
        return create_cors_response(trends, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

@manufacturer_integration_bp.route('/analytics/device-breakdown', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['analytics'])
def get_device_breakdown():
    """Get device verification breakdown"""
    try:
        time_range = request.args.get('time_range', '30d')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get device analytics
        device_data = analytics_service.get_device_analytics(manufacturer_id, time_range)
        
        return create_cors_response(device_data, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# LOGS API
# ===============================

@manufacturer_integration_bp.route('/logs/verifications', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['logs'])
def get_verification_logs():
    """
    Get verification logs for manufacturer
    
    Query parameters:
    - limit: Number of logs to return (max 100)
    - time_range: Time range (7d, 30d, 90d)
    - status: Filter by status (authentic, counterfeit)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        time_range = request.args.get('time_range', '30d')
        status_filter = request.args.get('status')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get verification logs
        logs = analytics_service.get_verification_logs(manufacturer_id, limit, time_range)
        
        # Apply status filter if provided
        if status_filter and status_filter.lower() in ['authentic', 'counterfeit']:
            filtered_logs = [
                log for log in logs['verificationLogs'] 
                if log['status'].lower() == status_filter.lower()
            ]
            logs['verificationLogs'] = filtered_logs
        
        # Add pagination metadata
        logs['pagination'] = {
            'limit': limit,
            'returned': len(logs['verificationLogs']),
            'has_more': len(logs['verificationLogs']) == limit
        }
        
        return create_cors_response(logs, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

@manufacturer_integration_bp.route('/logs/counterfeit-reports', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['logs'])
def get_counterfeit_reports():
    """Get counterfeit reports for manufacturer products"""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        time_range = request.args.get('time_range', '30d')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get counterfeit reports
        reports = manufacturer_service.get_manufacturer_counterfeit_reports(
            manufacturer_id, limit, time_range
        )
        
        return create_cors_response(reports, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# CUSTOMER DATA API
# ===============================

@manufacturer_integration_bp.route('/customers/verification-history/<customer_id>', methods=['GET'])
@api_key_required
@validate_manufacturer_access(['customer_data'])
def get_customer_verification_history(customer_id):
    """
    Get verification history for a specific customer
    (Only for products from this manufacturer)
    """
    try:
        time_range = request.args.get('time_range', '90d')
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        manufacturer_id = str(manufacturer_data['_id'])
        
        # Get customer verification history for this manufacturer only
        history = manufacturer_service.get_customer_manufacturer_history(
            customer_id, manufacturer_id, time_range
        )
        
        return create_cors_response(history, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# WEBHOOK CONFIGURATION
# ===============================

@manufacturer_integration_bp.route('/webhooks/configure', methods=['POST'])
@api_key_required
def configure_webhooks():
    """Configure webhook settings"""
    try:
        data = request.get_json()
        webhook_url = data.get('webhook_url')
        events = data.get('events', ['verification.completed', 'counterfeit.reported'])
        
        if not webhook_url:
            return create_cors_response({'error': 'webhook_url is required'}, 400)
        
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        
        # Update webhook configuration
        manufacturer_service.update_webhook_config(
            str(manufacturer_data['_id']), webhook_url, events
        )
        
        return create_cors_response({
            'status': 'success',
            'message': 'Webhook configuration updated',
            'webhook_url': webhook_url,
            'events': events
        }, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# RATE LIMITING INFO
# ===============================

@manufacturer_integration_bp.route('/usage/limits', methods=['GET'])
@api_key_required
def get_usage_limits():
    """Get current API usage and limits"""
    try:
        # Get manufacturer info
        api_key = request.headers.get('X-API-Key')
        manufacturer_data = manufacturer_service.get_manufacturer_by_api_key(api_key)
        
        # Get usage statistics
        usage_stats = manufacturer_service.get_api_usage_stats(str(manufacturer_data['_id']))
        
        return create_cors_response({
            'current_usage': usage_stats,
            'limits': {
                'verifications_per_hour': 1000,
                'verifications_per_day': 10000,
                'analytics_requests_per_hour': 100,
                'webhook_events_per_day': 5000
            },
            'reset_time': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }, 200)
        
    except Exception as e:
        return create_cors_response({'error': str(e)}, 500)

# ===============================
# UTILITY FUNCTIONS
# ===============================

def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """Verify webhook signature"""
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)

# Error handlers for the blueprint
@manufacturer_integration_bp.errorhandler(400)
def bad_request(error):
    return create_cors_response({'error': 'Bad request'}, 400)

@manufacturer_integration_bp.errorhandler(401)
def unauthorized(error):
    return create_cors_response({'error': 'Unauthorized'}, 401)

@manufacturer_integration_bp.errorhandler(403)
def forbidden(error):
    return create_cors_response({'error': 'Forbidden'}, 403)

@manufacturer_integration_bp.errorhandler(429)
def rate_limited(error):
    return create_cors_response({'error': 'Rate limit exceeded'}, 429)

@manufacturer_integration_bp.errorhandler(500)
def internal_error(error):
    return create_cors_response({'error': 'Internal server error'}, 500)