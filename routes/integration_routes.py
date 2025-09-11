# # routes/integration_routes.py
# from flask import Blueprint, request, jsonify
# from middleware.auth_middleware import api_key_required, validate_integration_access
# from services.manufacturer_service import ManufacturerService
# from utils.formatters import create_cors_response
# from datetime import datetime, timezone
# import traceback
# from bson import ObjectId

# integration_bp = Blueprint('integration', __name__)
# manufacturer_service = ManufacturerService()

# @integration_bp.route('/integration/manufacturer/register', methods=['POST'])
# def register_manufacturer_for_integration():
#     """
#     Register a new manufacturer specifically for platform integration
    
#     Expected payload:
#     {
#         "company_name": "Tech Corp Inc",
#         "email": "admin@techcorp.com",
#         "password": "secure_password",
#         "wallet_address": "0x123...",
#         "webhook_url": "https://techcorp.com/webhooks/verification",
#         "allowed_origins": ["https://techcorp.com", "https://admin.techcorp.com"],
#         "rate_limit": 2000,
#         "data_retention_days": 120
#     }
#     """
#     try:
#         data = request.get_json()
        
#         # Validate required fields
#         required_fields = ['company_name', 'email', 'password', 'wallet_address']
#         missing_fields = [field for field in required_fields if not data.get(field)]
        
#         if missing_fields:
#             return create_cors_response({
#                 "success": False,
#                 "error": f"Missing required fields: {', '.join(missing_fields)}"
#             }, 400)
        
#         # Create manufacturer account with integration setup
#         result = manufacturer_service.create_manufacturer_account(data)
        
#         if result.get("success"):
#             return create_cors_response({
#                 "success": True,
#                 "message": "Manufacturer account created successfully",
#                 "data": {
#                     "manufacturer_id": result["manufacturer_id"],
#                     "company_name": result["company_name"],
#                     "api_key": result["api_credentials"]["api_key"],  # Return only once
#                     "webhook_secret": result["api_credentials"]["webhook_secret"],
#                     "integration_id": result["integration_profile"]["integration_id"],
#                     "status": "pending_verification"  # Requires admin approval
#                 },
#                 "next_steps": [
#                     "Store your API key securely (it won't be shown again)",
#                     "Wait for admin verification of your account",
#                     "Configure webhook endpoint to receive notifications",
#                     "Test integration using the provided credentials"
#                 ]
#             }, 201)
#         else:
#             return create_cors_response({
#                 "success": False,
#                 "error": result.get("error", "Account creation failed")
#             }, 400)
            
#     except Exception as e:
#         print(f"Integration registration error: {e}")
#         return create_cors_response({
#             "success": False,
#             "error": "Internal server error"
#         }, 500)

# @integration_bp.route('/integration/manufacturer/data', methods=['GET'])
# @api_key_required
# @validate_integration_access
# def get_manufacturer_integration_data():
#     """
#     Get comprehensive data for manufacturer's integrated platform
    
#     Query parameters:
#     - time_range: 7d, 30d, 90d, 1y (default: 30d)
#     - include_logs: true/false (default: true)
#     - include_analytics: true/false (default: true)
#     - limit: number of logs to return (default: 100)
#     """
#     try:
#         # Get manufacturer ID from API key validation
#         manufacturer_id = request.manufacturer_id
        
#         # Get query parameters
#         time_range = request.args.get('time_range', '30d')
#         include_logs = request.args.get('include_logs', 'true').lower() == 'true'
#         include_analytics = request.args.get('include_analytics', 'true').lower() == 'true'
#         limit = int(request.args.get('limit', 100))
        
#         # Get comprehensive data
#         integration_data = manufacturer_service.get_manufacturer_integration_data(
#             manufacturer_id, 
#             time_range
#         )
        
#         if not integration_data.get("success", True):
#             return create_cors_response({
#                 "success": False,
#                 "error": integration_data.get("error", "Failed to fetch data")
#             }, 400)
        
#         # Filter data based on parameters
#         response_data = {
#             "success": True,
#             "manufacturer_info": integration_data["manufacturer_info"],
#             "products": integration_data["products"],
#             "time_range": integration_data["time_range"],
#             "integration_metrics": integration_data["integration_metrics"]
#         }
        
#         if include_logs:
#             # Limit verification logs
#             verification_logs = integration_data["verification_logs"][:limit]
#             counterfeit_reports = integration_data["counterfeit_reports"][:limit]
            
#             response_data.update({
#                 "verification_logs": verification_logs,
#                 "counterfeit_reports": counterfeit_reports,
#                 "logs_metadata": {
#                     "verification_logs_count": len(verification_logs),
#                     "counterfeit_reports_count": len(counterfeit_reports),
#                     "limit_applied": limit
#                 }
#             })
        
#         if include_analytics:
#             response_data["analytics"] = integration_data["analytics"]
        
#         # Update integration usage metrics
#         manufacturer_service.update_integration_usage(manufacturer_id)
        
#         return create_cors_response(response_data, 200)
        
#     except Exception as e:
#         print(f"Integration data fetch error: {e}")
#         traceback.print_exc()
#         return create_cors_response({
#             "success": False,
#             "error": "Failed to fetch integration data"
#         }, 500)

# @integration_bp.route('/integration/manufacturer/verification-logs', methods=['GET'])
# @api_key_required
# @validate_integration_access
# def get_verification_logs_for_integration():
#     """
#     Get detailed verification logs for manufacturer's platform
    
#     Query parameters:
#     - time_range: 7d, 30d, 90d, 1y (default: 30d)
#     - limit: number of logs to return (default: 50)
#     - offset: pagination offset (default: 0)
#     - status: authentic/counterfeit/all (default: all)
#     - customer_id: filter by specific customer
#     """
#     try:
#         manufacturer_id = request.manufacturer_id
        
#         # Get query parameters
#         time_range = request.args.get('time_range', '30d')
#         limit = int(request.args.get('limit', 50))
#         offset = int(request.args.get('offset', 0))
#         status_filter = request.args.get('status', 'all')
#         customer_id = request.args.get('customer_id')
        
#         # Calculate date range
#         from datetime import datetime, timezone, timedelta
#         end_date = datetime.now(timezone.utc)
#         days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
#         days = days_map.get(time_range, 30)
#         start_date = end_date - timedelta(days=days)
        
#         # Build match criteria
#         match_criteria = {
#             'manufacturer_id': manufacturer_id,
#             'created_at': {'$gte': start_date, '$lte': end_date}
#         }
        
#         if status_filter != 'all':
#             is_authentic = status_filter == 'authentic'
#             match_criteria['is_authentic'] = is_authentic
        
#         if customer_id:
#             from bson import ObjectId
#             match_criteria['customer_id'] = ObjectId(customer_id)
        
#         # Get verification logs with pagination
#         pipeline = [
#             {'$match': match_criteria},
#             {
#                 '$lookup': {
#                     'from': 'users',
#                     'localField': 'customer_id',
#                     'foreignField': '_id',
#                     'as': 'customer'
#                 }
#             },
#             {
#                 '$lookup': {
#                     'from': 'products',
#                     'localField': 'product_id',
#                     'foreignField': '_id',
#                     'as': 'product'
#                 }
#             },
#             {
#                 '$addFields': {
#                     'customer_data': {'$arrayElemAt': ['$customer', 0]},
#                     'product_data': {'$arrayElemAt': ['$product', 0]}
#                 }
#             },
#             {'$sort': {'created_at': -1}},
#             {'$skip': offset},
#             {'$limit': limit}
#         ]
        
#         from services.manufacturer_service import ManufacturerService
#         manufacturer_service = ManufacturerService()
#         db = manufacturer_service.db
        
#         verifications = list(db.verifications.aggregate(pipeline))
        
#         # Get total count for pagination
#         total_count = db.verifications.count_documents(match_criteria)
        
#         # Format logs
#         verification_logs = []
#         for verification in verifications:
#             customer_data = verification.get('customer_data', {})
#             product_data = verification.get('product_data', {})
            
#             log_entry = {
#                 'verification_id': str(verification['_id']),
#                 'serial_number': verification.get('serial_number'),
#                 'device_name': verification.get('device_name') or f"{product_data.get('brand', '')} {product_data.get('model', '')}".strip() or 'Unknown Device',
#                 'device_category': verification.get('device_category') or product_data.get('device_type') or 'Unknown',
#                 'is_authentic': verification.get('is_authentic'),
#                 'confidence_score': verification.get('confidence_score'),
#                 'response_time': verification.get('response_time'),
#                 'verification_method': verification.get('verification_method'),
#                 'customer_info': {
#                     'customer_id': str(verification.get('customer_id')) if verification.get('customer_id') else None,
#                     'email': customer_data.get('primary_email') if customer_data else None
#                 },
#                 'location_info': {
#                     'user_ip': verification.get('user_ip'),
#                     'user_agent': verification.get('user_agent')
#                 },
#                 'timestamp': verification.get('created_at').isoformat()
#             }
            
#             verification_logs.append(log_entry)
        
#         # Update integration usage
#         manufacturer_service.update_integration_usage(manufacturer_id)
        
#         return create_cors_response({
#             'success': True,
#             'data': {
#                 'verification_logs': verification_logs,
#                 'pagination': {
#                     'total_count': total_count,
#                     'limit': limit,
#                     'offset': offset,
#                     'has_more': (offset + limit) < total_count
#                 },
#                 'filters_applied': {
#                     'time_range': time_range,
#                     'status': status_filter,
#                     'customer_id': customer_id
#                 }
#             }
#         }, 200)
        
#     except Exception as e:
#         print(f"Verification logs fetch error: {e}")
#         return create_cors_response({
#             'success': False,
#             'error': 'Failed to fetch verification logs'
#         }, 500)

# @integration_bp.route('/integration/manufacturer/counterfeit-reports', methods=['GET'])
# @api_key_required
# @validate_integration_access
# def get_counterfeit_reports_for_integration():
#     """Get counterfeit reports for manufacturer's platform"""
#     try:
#         manufacturer_id = request.manufacturer_id
        
#         # Get query parameters
#         time_range = request.args.get('time_range', '30d')
#         limit = int(request.args.get('limit', 50))
#         offset = int(request.args.get('offset', 0))
#         status_filter = request.args.get('status', 'all')  # pending, investigated, resolved, all
        
#         # Calculate date range
#         from datetime import datetime, timezone, timedelta
#         end_date = datetime.now(timezone.utc)
#         days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
#         days = days_map.get(time_range, 30)
#         start_date = end_date - timedelta(days=days)
        
#         # Build match criteria
#         match_criteria = {
#             'manufacturer_id': manufacturer_id,
#             'created_at': {'$gte': start_date, '$lte': end_date}
#         }
        
#         if status_filter != 'all':
#             match_criteria['report_status'] = status_filter
        
#         # Get counterfeit reports with pagination
#         pipeline = [
#             {'$match': match_criteria},
#             {
#                 '$lookup': {
#                     'from': 'users',
#                     'localField': 'customer_id',
#                     'foreignField': '_id',
#                     'as': 'customer'
#                 }
#             },
#             {
#                 '$lookup': {
#                     'from': 'verifications',
#                     'localField': 'verification_id',
#                     'foreignField': '_id',
#                     'as': 'verification'
#                 }
#             },
#             {
#                 '$addFields': {
#                     'customer_data': {'$arrayElemAt': ['$customer', 0]},
#                     'verification_data': {'$arrayElemAt': ['$verification', 0]}
#                 }
#             },
#             {'$sort': {'created_at': -1}},
#             {'$skip': offset},
#             {'$limit': limit}
#         ]
        
#         from services.manufacturer_service import ManufacturerService
#         manufacturer_service = ManufacturerService()
#         db = manufacturer_service.db
        
#         reports = list(db.counterfeit_reports.aggregate(pipeline))
        
#         # Get total count
#         total_count = db.counterfeit_reports.count_documents(match_criteria)
        
#         # Format reports
#         counterfeit_reports = []
#         for report in reports:
#             customer_data = report.get('customer_data', {})
            
#             report_entry = {
#                 'report_id': str(report['_id']),
#                 'verification_id': str(report.get('verification_id')) if report.get('verification_id') else None,
#                 'serial_number': report.get('serial_number'),
#                 'product_name': report.get('product_name'),
#                 'device_category': report.get('device_category'),
#                 'customer_info': {
#                     'customer_id': str(report.get('customer_id')) if report.get('customer_id') else None,
#                     'email': customer_data.get('primary_email') if customer_data else None
#                 },
#                 'location_data': {
#                     'store_name': report.get('store_name'),
#                     'store_address': report.get('store_address'),
#                     'city': report.get('city'),
#                     'state': report.get('state')
#                 } if report.get('customer_consent') else None,
#                 'purchase_info': {
#                     'purchase_date': report.get('purchase_date').isoformat() if report.get('purchase_date') else None,
#                     'purchase_price': report.get('purchase_price')
#                 } if report.get('customer_consent') else None,
#                 'report_status': report.get('report_status', 'pending'),
#                 'additional_notes': report.get('additional_notes'),
#                 'timestamp': report.get('created_at').isoformat(),
#                 'has_consent': report.get('customer_consent', False)
#             }
            
#             counterfeit_reports.append(report_entry)
        
#         # Update integration usage
#         manufacturer_service.update_integration_usage(manufacturer_id)
        
#         return create_cors_response({
#             'success': True,
#             'data': {
#                 'counterfeit_reports': counterfeit_reports,
#                 'pagination': {
#                     'total_count': total_count,
#                     'limit': limit,
#                     'offset': offset,
#                     'has_more': (offset + limit) < total_count
#                 },
#                 'filters_applied': {
#                     'time_range': time_range,
#                     'status': status_filter
#                 }
#             }
#         }, 200)
        
#     except Exception as e:
#         print(f"Counterfeit reports fetch error: {e}")
#         return create_cors_response({
#             'success': False,
#             'error': 'Failed to fetch counterfeit reports'
#         }, 500)

# @integration_bp.route('/integration/manufacturer/analytics', methods=['GET'])
# @api_key_required
# @validate_integration_access
# def get_analytics_for_integration():
#     """Get comprehensive analytics for manufacturer's platform"""
#     try:
#         manufacturer_id = request.manufacturer_id
#         time_range = request.args.get('time_range', '30d')
        
#         # Get analytics data
#         integration_data = manufacturer_service.get_manufacturer_integration_data(
#             manufacturer_id, 
#             time_range
#         )
        
#         if not integration_data.get("success", True):
#             return create_cors_response({
#                 "success": False,
#                 "error": integration_data.get("error", "Failed to fetch analytics")
#             }, 400)
        
#         # Extract and enhance analytics
#         analytics = integration_data["analytics"]
        
#         # Add trending data
#         from datetime import datetime, timezone, timedelta
#         from bson import ObjectId
        
#         end_date = datetime.now(timezone.utc)
#         days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
#         days = days_map.get(time_range, 30)
#         start_date = end_date - timedelta(days=days)
        
#         # Daily verification trends
#         daily_trends = list(manufacturer_service.db.verifications.aggregate([
#             {
#                 '$match': {
#                     'manufacturer_id': ObjectId(manufacturer_id),
#                     'created_at': {'$gte': start_date, '$lte': end_date}
#                 }
#             },
#             {
#                 '$group': {
#                     '_id': {
#                         '$dateToString': {
#                             'format': '%Y-%m-%d',
#                             'date': '$created_at'
#                         }
#                     },
#                     'total_verifications': {'$sum': 1},
#                     'authentic_count': {'$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}},
#                     'counterfeit_count': {'$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}},
#                     'avg_response_time': {'$avg': '$response_time'}
#                 }
#             },
#             {'$sort': {'_id': 1}}
#         ]))
        
#         # Device category breakdown
#         device_breakdown = list(manufacturer_service.db.verifications.aggregate([
#             {
#                 '$match': {
#                     'manufacturer_id': ObjectId(manufacturer_id),
#                     'created_at': {'$gte': start_date, '$lte': end_date}
#                 }
#             },
#             {
#                 '$group': {
#                     '_id': '$device_category',
#                     'count': {'$sum': 1},
#                     'authentic': {'$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}},
#                     'counterfeit': {'$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}}
#                 }
#             },
#             {'$sort': {'count': -1}}
#         ]))
        
#         # Update integration usage
#         manufacturer_service.update_integration_usage(manufacturer_id)
        
#         return create_cors_response({
#             'success': True,
#             'data': {
#                 'summary': analytics,
#                 'daily_trends': [
#                     {
#                         'date': trend['_id'],
#                         'total_verifications': trend['total_verifications'],
#                         'authentic_count': trend['authentic_count'],
#                         'counterfeit_count': trend['counterfeit_count'],
#                         'avg_response_time': round(trend['avg_response_time'] or 0, 2)
#                     } for trend in daily_trends
#                 ],
#                 'device_breakdown': [
#                     {
#                         'category': breakdown['_id'] or 'Unknown',
#                         'total_count': breakdown['count'],
#                         'authentic_count': breakdown['authentic'],
#                         'counterfeit_count': breakdown['counterfeit'],
#                         'authenticity_rate': round((breakdown['authentic'] / breakdown['count']) * 100, 1)
#                     } for breakdown in device_breakdown
#                 ],
#                 'time_range': {
#                     'start_date': start_date.isoformat(),
#                     'end_date': end_date.isoformat(),
#                     'period': time_range
#                 }
#             }
#         }, 200)
        
#     except Exception as e:
#         print(f"Analytics fetch error: {e}")
#         return create_cors_response({
#             'success': False,
#             'error': 'Failed to fetch analytics data'
#         }, 500)

# @integration_bp.route('/integration/manufacturer/webhook-test', methods=['POST'])
# @api_key_required
# @validate_integration_access
# def test_webhook_integration():
#     """Test webhook integration for manufacturer"""
#     try:
#         manufacturer_id = request.manufacturer_id
#         data = request.get_json()
        
#         webhook_url = data.get('webhook_url')
#         if not webhook_url:
#             return create_cors_response({
#                 'success': False,
#                 'error': 'webhook_url is required'
#             }, 400)
        
#         # Create test payload
#         test_payload = {
#             'event': 'webhook_test',
#             'manufacturer_id': manufacturer_id,
#             'timestamp': datetime.now(timezone.utc).isoformat(),
#             'data': {
#                 'message': 'This is a test webhook from the verification system',
#                 'test_id': str(ObjectId())
#             }
#         }
        
#         # Send test webhook (implement webhook sending logic)
#         import requests
#         import hmac
#         import hashlib
        
#         # Get webhook secret
#         integration = manufacturer_service.db.integrations.find_one({
#             'manufacturer_id': ObjectId(manufacturer_id)
#         })
        
#         if not integration:
#             return create_cors_response({
#                 'success': False,
#                 'error': 'Integration not configured'
#             }, 400)
        
#         # Get API key to get webhook secret
#         api_key_doc = manufacturer_service.db.api_keys.find_one({
#             'user_id': ObjectId(manufacturer_id),
#             'is_active': True
#         })
        
#         webhook_secret = api_key_doc.get('webhook_secret') if api_key_doc else None
        
#         if not webhook_secret:
#             return create_cors_response({
#                 'success': False,
#                 'error': 'Webhook secret not found'
#             }, 400)
        
#         # Create signature
#         payload_str = str(test_payload)
#         signature = hmac.new(
#             webhook_secret.encode('utf-8'),
#             payload_str.encode('utf-8'),
#             hashlib.sha256
#         ).hexdigest()
        
#         # Send webhook
#         headers = {
#             'Content-Type': 'application/json',
#             'X-Webhook-Signature': f'sha256={signature}',
#             'User-Agent': 'VerificationSystem-Webhook/1.0'
#         }
        
#         try:
#             response = requests.post(
#                 webhook_url,
#                 json=test_payload,
#                 headers=headers,
#                 timeout=10
#             )
            
#             success = response.status_code == 200
            
#             # Log webhook attempt
#             webhook_log = {
#                 'manufacturer_id': ObjectId(manufacturer_id),
#                 'webhook_url': webhook_url,
#                 'event': 'webhook_test',
#                 'status_code': response.status_code,
#                 'success': success,
#                 'response_body': response.text[:1000],  # Limit response body
#                 'timestamp': datetime.now(timezone.utc)
#             }
            
#             manufacturer_service.db.webhook_logs.insert_one(webhook_log)
            
#             return create_cors_response({
#                 'success': True,
#                 'webhook_test_result': {
#                     'webhook_url': webhook_url,
#                     'status_code': response.status_code,
#                     'response_time': response.elapsed.total_seconds(),
#                     'success': success,
#                     'message': 'Test webhook sent successfully' if success else 'Webhook failed'
#                 }
#             }, 200)
            
#         except requests.RequestException as req_error:
#             return create_cors_response({
#                 'success': False,
#                 'error': f'Webhook request failed: {str(req_error)}'
#             }, 400)
        
#     except Exception as e:
#         print(f"Webhook test error: {e}")
#         return create_cors_response({
#             'success': False,
#             'error': 'Failed to test webhook'
#         }, 500)

# # Utility route to get integration status
# @integration_bp.route('/integration/manufacturer/status', methods=['GET'])
# @api_key_required
# @validate_integration_access
# def get_integration_status():
#     """Get current integration status and configuration"""
#     try:
#         manufacturer_id = request.manufacturer_id
        
#         # Get manufacturer info
#         manufacturer = manufacturer_service.db.users.find_one({
#             '_id': ObjectId(manufacturer_id)
#         })
        
#         if not manufacturer:
#             return create_cors_response({
#                 'success': False,
#                 'error': 'Manufacturer not found'
#             }, 404)
        
#         # Get integration info
#         integration = manufacturer_service.db.integrations.find_one({
#             'manufacturer_id': ObjectId(manufacturer_id)
#         })
        
#         # Get API key info
#         api_key = manufacturer_service.db.api_keys.find_one({
#             'user_id': ObjectId(manufacturer_id),
#             'is_active': True
#         })
        
#         status_info = {
#             'manufacturer_info': {
#                 'id': str(manufacturer['_id']),
#                 'company_name': manufacturer.get('current_company_name'),
#                 'verification_status': manufacturer.get('verification_status'),
#                 'created_at': manufacturer.get('created_at').isoformat()
#             },
#             'integration_status': {
#                 'is_active': bool(integration and integration.get('status') == 'active'),
#                 'integration_id': str(integration['_id']) if integration else None,
#                 'configuration': integration.get('configuration', {}) if integration else {},
#                 'usage_metrics': integration.get('usage_metrics', {}) if integration else {}
#             },
#             'api_key_info': {
#                 'has_active_key': bool(api_key),
#                 'key_type': api_key.get('key_type') if api_key else None,
#                 'permissions': api_key.get('permissions', []) if api_key else [],
#                 'rate_limit': api_key.get('rate_limit') if api_key else None,
#                 'created_at': api_key.get('created_at').isoformat() if api_key else None
#             }
#         }
        
#         return create_cors_response({
#             'success': True,
#             'data': status_info
#         }, 200)
        
#     except Exception as e:
#         print(f"Integration status error: {e}")
#         return create_cors_response({
#             'success': False,
#             'error': 'Failed to get integration status'
#         }, 500)

"""
Integration Routes for Manufacturer Platform Integration

This module provides REST API endpoints for manufacturer platform integration,
including account management, customer logs, and analytics.
"""

from flask import Blueprint, request, jsonify, make_response
from functools import wraps
from datetime import datetime, timezone
from bson import ObjectId
import traceback

# Import your existing utilities from app.py
from services.integration_service import manufacturer_integration
from utils.helper_functions import get_db_connection, ValidationError, AuthenticationError

# Create Blueprint
integration_bp = Blueprint('integration', __name__, url_prefix='/api/v1/integration')

def add_cors_headers(response):
    """Add CORS headers to response"""
    origin = request.headers.get('Origin')
    allowed_origins = [
        'http://localhost:3000',
        'http://localhost:5173',
        'https://blockchain-verification-esup.vercel.app'
    ]
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = allowed_origins[0]
    
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-API-Key,Accept,Origin'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

def create_cors_response(data, status_code=200):
    """Helper function to create CORS-enabled responses"""
    response = make_response(jsonify(data), status_code)
    return add_cors_headers(response)

def api_key_required(permission=None):
    """Decorator for API key authentication with permission checking"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            
            if not api_key:
                return create_cors_response({
                    'error': 'API key is required',
                    'code': 'MISSING_API_KEY'
                }, 401)
            
            # Validate API key
            key_data = manufacturer_integration.validate_api_key(api_key, permission)
            
            if not key_data:
                return create_cors_response({
                    'error': 'Invalid API key or insufficient permissions',
                    'code': 'INVALID_API_KEY'
                }, 401)
            
            # Add key data to request context
            request.api_key_data = key_data
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# ===============================
# MANUFACTURER ACCOUNT MANAGEMENT
# ===============================

@integration_bp.route('/manufacturer/create-account', methods=['POST', 'OPTIONS'])
def create_manufacturer_account():
    """Create a new manufacturer account for integration"""
    if request.method == 'OPTIONS':
        response = make_response()
        return add_cors_headers(response)
    
    try:
        data = request.get_json()
        
        if not data:
            return create_cors_response({
                'error': 'Request body is required',
                'code': 'MISSING_BODY'
            }, 400)
        
        # Create account using integration service
        result = manufacturer_integration.create_manufacturer_account(data)
        
        return create_cors_response(result, 201)
        
    except ValidationError as e:
        return create_cors_response({
            'error': str(e),
            'code': 'VALIDATION_ERROR'
        }, 400)
    except Exception as e:
        print(f"Create manufacturer account error: {e}")
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

@integration_bp.route('/manufacturer/<manufacturer_id>/profile', methods=['GET'])
@api_key_required('manufacturer.profile.read')
def get_manufacturer_profile(manufacturer_id):
    """Get manufacturer profile information"""
    try:
        # Verify manufacturer exists and API key has access
        key_data = request.api_key_data
        
        if str(key_data['user_id']) != manufacturer_id:
            return create_cors_response({
                'error': 'Unauthorized access to this manufacturer profile',
                'code': 'UNAUTHORIZED_ACCESS'
            }, 403)
        
        # Get manufacturer data
        from utils.helper_functions import get_user_by_id, format_user_profile
        
        manufacturer = get_user_by_id(manufacturer_id)
        if not manufacturer:
            return create_cors_response({
                'error': 'Manufacturer not found',
                'code': 'NOT_FOUND'
            }, 404)
        
        profile_data = format_user_profile(manufacturer)
        
        return create_cors_response({
            'status': 'success',
            'manufacturer': profile_data
        }, 200)
        
    except Exception as e:
        print(f"Get manufacturer profile error: {e}")
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

# ===============================
# CUSTOMER LOGS AND ANALYTICS
# ===============================

@integration_bp.route('/manufacturer/<manufacturer_id>/customer-logs', methods=['GET'])
@api_key_required('customer.logs.read')
def get_customer_logs(manufacturer_id):
    """Get customer logs (verifications, counterfeit reports) for manufacturer"""
    try:
        # Verify API key has access to this manufacturer
        key_data = request.api_key_data
        
        if str(key_data['user_id']) != manufacturer_id:
            return create_cors_response({
                'error': 'Unauthorized access to this manufacturer data',
                'code': 'UNAUTHORIZED_ACCESS'
            }, 403)
        
        # Parse query parameters
        log_type = request.args.get('type', 'all')  # 'verification', 'counterfeit', 'all'
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000
        offset = int(request.args.get('offset', 0))
        
        # Date filters
        date_from = None
        date_to = None
        
        if request.args.get('date_from'):
            try:
                date_from = datetime.fromisoformat(request.args.get('date_from'))
            except ValueError:
                return create_cors_response({
                    'error': 'Invalid date_from format. Use ISO format (YYYY-MM-DD)',
                    'code': 'INVALID_DATE_FORMAT'
                }, 400)
        
        if request.args.get('date_to'):
            try:
                date_to = datetime.fromisoformat(request.args.get('date_to'))
            except ValueError:
                return create_cors_response({
                    'error': 'Invalid date_to format. Use ISO format (YYYY-MM-DD)',
                    'code': 'INVALID_DATE_FORMAT'
                }, 400)
        
        # Fetch logs using integration service
        result = manufacturer_integration.get_customer_logs(
            manufacturer_id=manufacturer_id,
            log_type=log_type,
            limit=limit,
            offset=offset,
            date_from=date_from,
            date_to=date_to
        )
        
        return create_cors_response(result, 200)
        
    except AuthenticationError as e:
        return create_cors_response({
            'error': str(e),
            'code': 'AUTH_ERROR'
        }, 401)
    except Exception as e:
        print(f"Get customer logs error: {e}")
        traceback.print_exc()
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

@integration_bp.route('/manufacturer/<manufacturer_id>/analytics', methods=['GET'])
@api_key_required('analytics.read')
def get_manufacturer_analytics(manufacturer_id):
    """Get analytics data for manufacturer"""
    try:
        # Verify API key has access to this manufacturer
        key_data = request.api_key_data
        
        if str(key_data['user_id']) != manufacturer_id:
            return create_cors_response({
                'error': 'Unauthorized access to this manufacturer analytics',
                'code': 'UNAUTHORIZED_ACCESS'
            }, 403)
        
        # Parse time period parameter
        time_period = request.args.get('period', '30d')
        valid_periods = ['7d', '30d', '90d', '1y']
        
        if time_period not in valid_periods:
            return create_cors_response({
                'error': f'Invalid time period. Must be one of: {", ".join(valid_periods)}',
                'code': 'INVALID_PERIOD'
            }, 400)
        
        # Get analytics using integration service
        result = manufacturer_integration.get_manufacturer_analytics(
            manufacturer_id=manufacturer_id,
            time_period=time_period
        )
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Get manufacturer analytics error: {e}")
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

# ===============================
# PRODUCT VERIFICATION INTEGRATION
# ===============================

@integration_bp.route('/manufacturer/<manufacturer_id>/products/<serial_number>/verify', methods=['GET'])
@api_key_required('product.verify')
def verify_product_integration(manufacturer_id, serial_number):
    """Verify a specific product for integrated manufacturer platform"""
    try:
        # Verify API key has access to this manufacturer
        key_data = request.api_key_data
        
        if str(key_data['user_id']) != manufacturer_id:
            return create_cors_response({
                'error': 'Unauthorized access to this manufacturer data',
                'code': 'UNAUTHORIZED_ACCESS'
            }, 403)
        
        # Import verification functions from your existing code
        from utils.helper_functions import get_product_by_serial, verify_product_on_blockchain
        
        # Get product from database
        product = get_product_by_serial(serial_number)
        
        if not product:
            return create_cors_response({
                'error': 'Product not found',
                'code': 'PRODUCT_NOT_FOUND',
                'serial_number': serial_number
            }, 404)
        
        # Verify manufacturer owns this product
        if str(product.get('manufacturer_id')) != manufacturer_id:
            return create_cors_response({
                'error': 'Product does not belong to this manufacturer',
                'code': 'UNAUTHORIZED_PRODUCT'
            }, 403)
        
        # Perform verification
        verification_result = {
            'serial_number': serial_number,
            'authentic': True,
            'source': 'database',
            'product_details': {
                'brand': product.get('brand'),
                'model': product.get('model'),
                'device_type': product.get('device_type'),
                'color': product.get('color'),
                'storage': product.get('storage_data'),
                'manufacturer_name': product.get('manufacturer_name')
            },
            'registration_details': {
                'registered_at': product.get('registered_at'),
                'blockchain_verified': product.get('blockchain_verified', False),
                'transaction_hash': product.get('transaction_hash')
            }
        }
        
        # Try blockchain verification if enabled
        if product.get('blockchain_verified'):
            try:
                blockchain_result = verify_product_on_blockchain(serial_number)
                if blockchain_result.get('verified'):
                    verification_result['source'] = 'blockchain'
                    verification_result['blockchain_proof'] = blockchain_result.get('proof')
            except Exception as e:
                print(f"Blockchain verification failed: {e}")
                verification_result['blockchain_error'] = str(e)
        
        return create_cors_response({
            'status': 'success',
            'verification': verification_result
        }, 200)
        
    except Exception as e:
        print(f"Product verification error: {e}")
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

@integration_bp.route('/manufacturer/<manufacturer_id>/products', methods=['GET'])
@api_key_required('product.list')
def list_manufacturer_products(manufacturer_id):
    """List all products for a manufacturer"""
    try:
        # Verify API key has access to this manufacturer
        key_data = request.api_key_data
        
        if str(key_data['user_id']) != manufacturer_id:
            return create_cors_response({
                'error': 'Unauthorized access to this manufacturer data',
                'code': 'UNAUTHORIZED_ACCESS'
            }, 403)
        
        # Parse query parameters
        limit = min(int(request.args.get('limit', 50)), 500)  # Max 500
        offset = int(request.args.get('offset', 0))
        status_filter = request.args.get('status')  # 'blockchain_confirmed', 'blockchain_pending', etc.
        
        # Import database functions
        from utils.helper_functions import get_user_by_id
        
        manufacturer = get_user_by_id(manufacturer_id)
        if not manufacturer:
            return create_cors_response({
                'error': 'Manufacturer not found',
                'code': 'MANUFACTURER_NOT_FOUND'
            }, 404)
        
        manufacturer_wallet = manufacturer.get('primary_wallet')
        if not manufacturer_wallet:
            return create_cors_response({
                'error': 'Manufacturer wallet not configured',
                'code': 'WALLET_NOT_CONFIGURED'
            }, 400)
        
        # Build query
        db = get_db_connection()
        query = {"manufacturer_wallet": manufacturer_wallet}
        
        if status_filter:
            query["registration_type"] = status_filter
        
        # Get total count
        total_count = db.products.count_documents(query)
        
        # Get products with pagination
        products = list(
            db.products.find(query)
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        
        # Format products for response
        formatted_products = []
        for product in products:
            formatted_products.append({
                'id': str(product.get('_id')),
                'serial_number': product.get('serial_number'),
                'brand': product.get('brand'),
                'model': product.get('model'),
                'device_type': product.get('device_type'),
                'registration_type': product.get('registration_type'),
                'blockchain_verified': product.get('blockchain_verified', False),
                'transaction_hash': product.get('transaction_hash'),
                'created_at': product.get('created_at'),
                'registered_at': product.get('registered_at')
            })
        
        return create_cors_response({
            'status': 'success',
            'products': formatted_products,
            'pagination': {
                'total_count': total_count,
                'returned_count': len(formatted_products),
                'limit': limit,
                'offset': offset,
                'has_more': (offset + len(formatted_products)) < total_count
            }
        }, 200)
        
    except Exception as e:
        print(f"List products error: {e}")
        return create_cors_response({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }, 500)

# ===============================
# WEBHOOK ENDPOINTS
# ===============================

@integration_bp.route('/webhook/verification', methods=['POST'])
@api_key_required('webhook.receive')
def webhook_verification_event():
    """Receive verification event webhooks from manufacturer platforms"""
    try:
        data = request.get_json()
        
        if not data:
            return create_cors_response({
                'error': 'Webhook payload is required',
                'code': 'MISSING_PAYLOAD'
            }, 400)
        
        # Validate webhook payload
        required_fields = ['event_type', 'serial_number', 'timestamp']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}',
                'code': 'INVALID_PAYLOAD'
            }, 400)
        
        # Process webhook based on event type
        event_type = data.get('event_type')
        
        if event_type == 'verification_requested':
            result = process_verification_webhook(data)
        elif event_type == 'counterfeit_reported':
            result = process_counterfeit_webhook(data)
        else:
            return create_cors_response({
                'error': f'Unsupported event type: {event_type}',
                'code': 'UNSUPPORTED_EVENT'
            }, 400)
        
        return create_cors_response({
            'status': 'success',
            'message': 'Webhook processed successfully',
            'result': result
        }, 200)
        
    except Exception as e:
        print(f"Webhook processing error: {e}")
        return create_cors_response({
            'error': 'Webhook processing failed',
            'code': 'WEBHOOK_ERROR'
        }, 500)

def process_verification_webhook(data):
    """Process verification webhook event"""
    try:
        db = get_db_connection()
        
        # Log the verification event
        verification_log = {
            'serial_number': data.get('serial_number'),
            'event_type': 'webhook_verification',
            'customer_id': data.get('customer_id'),
            'manufacturer_platform': data.get('platform_name'),
            'verification_method': 'webhook',
            'timestamp': datetime.now(timezone.utc),
            'webhook_data': data,
            'processed_at': datetime.now(timezone.utc)
        }
        
        result = db.webhook_events.insert_one(verification_log)
        
        return {
            'event_id': str(result.inserted_id),
            'processed': True
        }
        
    except Exception as e:
        print(f"Verification webhook processing error: {e}")
        raise

def process_counterfeit_webhook(data):
    """Process counterfeit report webhook event"""
    try:
        db = get_db_connection()
        
        # Create counterfeit report
        report = {
            'serial_number': data.get('serial_number'),
            'reporter_platform': data.get('platform_name'),
            'reporter_id': data.get('customer_id'),
            'reason': data.get('reason', 'Reported via webhook'),
            'description': data.get('description', ''),
            'evidence': data.get('evidence', []),
            'status': 'pending',
            'source': 'webhook',
            'timestamp': datetime.now(timezone.utc),
            'webhook_data': data,
            'created_at': datetime.now(timezone.utc)
        }
        
        result = db.counterfeit_reports.insert_one(report)
        
        return {
            'report_id': str(result.inserted_id),
            'status': 'pending',
            'processed': True
        }
        
    except Exception as e:
        print(f"Counterfeit webhook processing error: {e}")
        raise

# ===============================
# API HEALTH AND STATUS
# ===============================

@integration_bp.route('/health', methods=['GET'])
def api_health():
    """API health check endpoint"""
    try:
        db = get_db_connection()
        
        # Test database connection
        db.users.count_documents({}, limit=1)
        
        return create_cors_response({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'services': {
                'database': 'connected',
                'integration_service': 'active'
            }
        }, 200)
        
    except Exception as e:
        print(f"Health check error: {e}")
        return create_cors_response({
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': 'Database connection failed'
        }, 503)

@integration_bp.route('/api-key/validate', methods=['GET'])
@api_key_required()
def validate_api_key_endpoint():
    """Validate API key and return information about it"""
    try:
        key_data = request.api_key_data
        
        return create_cors_response({
            'status': 'valid',
            'key_type': key_data.get('key_type'),
            'permissions': key_data.get('permissions', []),
            'usage_count': key_data.get('usage_count', 0),
            'last_used': key_data.get('last_used'),
            'manufacturer_id': str(key_data.get('user_id'))
        }, 200)
        
    except Exception as e:
        print(f"API key validation error: {e}")
        return create_cors_response({
            'error': 'API key validation failed',
            'code': 'VALIDATION_ERROR'
        }, 500)

# Handle preflight requests for all integration routes
@integration_bp.before_request
def handle_integration_preflight():
    """Handle preflight OPTIONS requests for integration routes"""
    if request.method == "OPTIONS":
        response = make_response()
        return add_cors_headers(response)