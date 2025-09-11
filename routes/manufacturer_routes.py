# routes/manufacturer_routes.py
from flask import Blueprint, request, jsonify, make_response
from datetime import datetime, timezone
from bson import ObjectId
from functools import wraps
import secrets
import hashlib
import jwt
import os

# Import your helper functions (keeping your existing imports)
from utils.helper_functions import (
    get_user_by_email, get_user_by_id, create_user, get_db_connection,
    hash_password, validate_user_registration, ValidationError,
    get_current_utc, format_user_profile, is_valid_email, is_valid_wallet_address,
    email_exists_globally, wallet_exists_globally
)

manufacturer_bp = Blueprint('manufacturer', __name__)

# CORS helper from your main app
def create_cors_response(data, status_code=200):
    """Helper function to create CORS-enabled responses"""
    response = make_response(jsonify(data), status_code)
    
    # Add CORS headers
    allowed_origins = [
        'http://localhost:3000',
        'http://localhost:5173',
        'https://blockchain-verification-esup.vercel.app'
    ]
    
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = allowed_origins[0]
    
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-API-Key'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

# Authentication decorator
def token_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return create_cors_response({'message': 'Invalid token format'}, 401)
        
        if not token:
            return create_cors_response({'message': 'Token is missing'}, 401)
        
        try:
            data = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS256'])
            current_user_id = data['sub']
            current_user_role = data.get('role')
            
        except jwt.ExpiredSignatureError:
            return create_cors_response({'message': 'Token has expired'}, 401)
        except jwt.InvalidTokenError:
            return create_cors_response({'message': 'Invalid token'}, 401)
        except Exception:
            return create_cors_response({'message': 'Token verification failed'}, 401)
        
        return f(current_user_id, current_user_role, *args, **kwargs)
    return decorated

def api_key_required(f):
    """Decorator for API key authentication for integration partners"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return create_cors_response({'message': 'API key is required'}, 401)
        
        # Validate API key
        db = get_db_connection()
        key_data = db.api_keys.find_one({
            'key_hash': hashlib.sha256(api_key.encode()).hexdigest(),
            'status': 'active'
        })
        
        if not key_data:
            return create_cors_response({'message': 'Invalid API key'}, 401)
        
        # Update last used
        db.api_keys.update_one(
            {'_id': key_data['_id']},
            {'$set': {'last_used': datetime.now(timezone.utc)}}
        )
        
        # Add manufacturer info to request context
        request.api_manufacturer_id = key_data['manufacturer_id']
        request.api_key_permissions = key_data.get('permissions', [])
        
        return f(*args, **kwargs)
    return decorated

# ======================================================
# MANUFACTURER ACCOUNT CREATION & MANAGEMENT ROUTES
# ======================================================

@manufacturer_bp.route('/create-account', methods=['POST'])
@api_key_required
def create_manufacturer_account():
    """
    Create manufacturer account via API integration
    This endpoint is for platforms integrating with our system
    """
    try:
        data = request.get_json()
        
        # Validate required fields for API account creation
        required_fields = ['email', 'company_name', 'wallet_address', 'contact_person']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        email = data['email'].strip().lower()
        company_name = data['company_name'].strip()
        wallet_address = data['wallet_address'].strip()
        contact_person = data.get('contact_person', '').strip()
        
        # Validation
        if not is_valid_email(email):
            return create_cors_response({'error': 'Invalid email format'}, 400)
        
        if not is_valid_wallet_address(wallet_address):
            return create_cors_response({'error': 'Invalid wallet address format'}, 400)
        
        if email_exists_globally(email, None):
            return create_cors_response({'error': 'Email already registered'}, 400)
        
        if wallet_exists_globally(wallet_address, None):
            return create_cors_response({'error': 'Wallet address already registered'}, 400)
        
        # Generate secure password for API-created accounts
        temp_password = secrets.token_urlsafe(16)
        password_hash = hash_password(temp_password)
        
        # Create manufacturer account
        user_data = {
            "emails": [email],
            "primary_email": email,
            "password_hash": password_hash,
            "role": "manufacturer",
            "verification_status": "api_created",  # Special status for API-created accounts
            
            # Manufacturer specific fields
            "wallet_addresses": [wallet_address],
            "primary_wallet": wallet_address,
            "verified_wallets": [],  # Will need verification
            "company_names": [company_name],
            "current_company_name": company_name,
            
            # Integration metadata
            "created_via_api": True,
            "creating_api_key": request.api_manufacturer_id,
            "contact_person": contact_person,
            "integration_settings": {
                "auto_approve_products": data.get('auto_approve_products', False),
                "webhook_notifications": data.get('webhook_notifications', False),
                "sync_frequency": data.get('sync_frequency', 'manual')
            },
            
            # Timestamps
            "created_at": get_current_utc(),
            "updated_at": get_current_utc()
        }
        
        # Add optional fields
        optional_fields = ['phone', 'address', 'country', 'website', 'description']
        for field in optional_fields:
            if data.get(field):
                user_data[field] = data[field].strip()
        
        user_id = create_user(user_data)
        
        # Generate API key for the new manufacturer
        api_key = secrets.token_urlsafe(32)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        db = get_db_connection()
        db.api_keys.insert_one({
            'manufacturer_id': ObjectId(user_id),
            'name': f'Default API Key - {company_name}',
            'key_hash': api_key_hash,
            'permissions': ['verify', 'register_products', 'analytics'],
            'status': 'active',
            'created_at': get_current_utc()
        })
        
        # Don't return the actual password or API key in production
        response_data = {
            'status': 'success',
            'message': 'Manufacturer account created successfully',
            'manufacturer_id': user_id,
            'email': email,
            'company_name': company_name,
            'verification_status': 'api_created'
        }
        
        # In development/testing, include credentials
        if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
            response_data.update({
                'temporary_password': temp_password,
                'api_key': api_key,
                'note': 'Store these credentials securely. Password should be changed on first login.'
            })
        
        return create_cors_response(response_data, 201)
        
    except ValidationError as e:
        return create_cors_response({'error': str(e)}, 400)
    except Exception as e:
        print(f"Account creation error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/create-integration', methods=['POST'])
@token_required
def create_integration_config(current_user_id, current_user_role):
    """Create integration configuration for a manufacturer"""
    try:
        data = request.get_json()
        
        # Get current user
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        if user.get('verification_status') != 'verified':
            return create_cors_response({'error': 'Account must be verified first'}, 403)
        
        # Validate integration data
        required_fields = ['integration_name', 'platform_type']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return create_cors_response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, 400)
        
        # Generate API credentials
        api_key = secrets.token_urlsafe(32)
        webhook_secret = secrets.token_urlsafe(24)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        db = get_db_connection()
        
        # Create integration record
        integration_data = {
            'manufacturer_id': ObjectId(current_user_id),
            'integration_name': data['integration_name'],
            'platform_type': data['platform_type'],
            
            # API Configuration
            'api_endpoint': data.get('api_endpoint', ''),
            'webhook_url': data.get('webhook_url', ''),
            'webhook_secret': webhook_secret,
            
            # Integration settings
            'sync_settings': data.get('sync_settings', {}),
            'data_mapping': data.get('data_mapping', {}),
            'filters': data.get('filters', {}),
            
            # Status
            'status': 'inactive',
            'created_at': get_current_utc(),
            'updated_at': get_current_utc()
        }
        
        result = db.manufacturer_integrations.insert_one(integration_data)
        integration_id = str(result.inserted_id)
        
        # Create API key
        db.api_keys.insert_one({
            'manufacturer_id': ObjectId(current_user_id),
            'integration_id': ObjectId(integration_id),
            'name': f'{data["integration_name"]} API Key',
            'key_hash': api_key_hash,
            'permissions': data.get('permissions', ['verify', 'register_products', 'analytics']),
            'status': 'active',
            'created_at': get_current_utc()
        })
        
        response_data = {
            'status': 'success',
            'message': 'Integration created successfully',
            'integration_id': integration_id,
            'webhook_secret': webhook_secret
        }
        
        # Include API key in development
        if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
            response_data['api_key'] = api_key
        
        return create_cors_response(response_data, 201)
        
    except Exception as e:
        print(f"Integration creation error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

# ======================================================
# MANUFACTURER ANALYTICS & DATA RETRIEVAL ROUTES
# ======================================================

@manufacturer_bp.route('/verification-logs', methods=['GET'])
@api_key_required  
def get_manufacturer_verification_logs_api():
    """
    Get verification logs for integrated manufacturer platforms
    Supports filtering and pagination
    """
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        serial_number = request.args.get('serial_number')
        status = request.args.get('status')  # 'authentic', 'counterfeit'
        
        manufacturer_id = request.api_manufacturer_id
        
        # Build query
        query = {'manufacturer_id': manufacturer_id}
        
        # Date range filter
        if start_date or end_date:
            date_filter = {}
            if start_date:
                date_filter['$gte'] = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if end_date:
                date_filter['$lte'] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query['created_at'] = date_filter
        
        # Serial number filter
        if serial_number:
            query['serial_number'] = serial_number
        
        # Status filter  
        if status:
            query['is_authentic'] = status == 'authentic'
        
        db = get_db_connection()
        
        # Get total count
        total_count = db.verifications.count_documents(query)
        
        # Get paginated results with enriched data
        pipeline = [
            {'$match': query},
            {
                '$lookup': {
                    'from': 'products',
                    'localField': 'product_id', 
                    'foreignField': '_id',
                    'as': 'product'
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'customer_id',
                    'foreignField': '_id', 
                    'as': 'customer'
                }
            },
            {
                '$lookup': {
                    'from': 'counterfeit_reports',
                    'localField': '_id',
                    'foreignField': 'verification_id',
                    'as': 'counterfeit_report'
                }
            },
            {'$sort': {'created_at': -1}},
            {'$skip': offset},
            {'$limit': limit}
        ]
        
        verifications = list(db.verifications.aggregate(pipeline))
        
        # Format response
        verification_logs = []
        for verification in verifications:
            product = verification.get('product', [{}])[0] if verification.get('product') else {}
            customer = verification.get('customer', [{}])[0] if verification.get('customer') else {}
            counterfeit_report = verification.get('counterfeit_report', [{}])[0] if verification.get('counterfeit_report') else {}
            
            # Get device name from multiple sources
            device_name = (
                verification.get('device_name') or
                counterfeit_report.get('product_name') or
                f"{product.get('brand', 'Unknown')} {product.get('model', 'Product')}"
            ).strip()
            
            log_entry = {
                'verification_id': str(verification['_id']),
                'serial_number': verification['serial_number'],
                'device_name': device_name,
                'device_category': (
                    verification.get('device_category') or 
                    counterfeit_report.get('device_category') or
                    product.get('device_type') or
                    'Unknown'
                ),
                'status': 'authentic' if verification['is_authentic'] else 'counterfeit',
                'confidence_score': verification.get('confidence_score', 0),
                'response_time': verification.get('response_time', 0),
                'verification_method': verification.get('verification_method', 'manual'),
                'timestamp': verification['created_at'].isoformat(),
                
                # Customer info (anonymized for privacy)
                'customer_id': str(verification['customer_id']) if verification.get('customer_id') else None,
                'customer_email': customer.get('primary_email', 'Unknown'),
                
                # Product info
                'product_id': str(verification['product_id']) if verification.get('product_id') else None,
                'brand': product.get('brand'),
                'model': product.get('model'),
                
                # Counterfeit info if applicable
                'counterfeit_report_id': str(counterfeit_report['_id']) if counterfeit_report.get('_id') else None
            }
            
            verification_logs.append(log_entry)
        
        return create_cors_response({
            'status': 'success',
            'data': {
                'verification_logs': verification_logs,
                'pagination': {
                    'total_count': total_count,
                    'limit': limit,
                    'offset': offset,
                    'has_next': offset + limit < total_count
                }
            }
        }, 200)
        
    except Exception as e:
        print(f"API verification logs error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/counterfeit-reports', methods=['GET'])
@api_key_required
def get_manufacturer_counterfeit_reports_api():
    """Get counterfeit reports for integrated manufacturer platforms"""
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        status = request.args.get('status')  # 'pending', 'verified', 'resolved'
        
        manufacturer_id = request.api_manufacturer_id
        
        # Build query
        query = {'manufacturer_id': manufacturer_id}
        
        # Date range filter
        if start_date or end_date:
            date_filter = {}
            if start_date:
                date_filter['$gte'] = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if end_date:
                date_filter['$lte'] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query['created_at'] = date_filter
        
        # Status filter
        if status:
            query['report_status'] = status
        
        db = get_db_connection()
        
        # Get total count
        total_count = db.counterfeit_reports.count_documents(query)
        
        # Get paginated results
        pipeline = [
            {'$match': query},
            {
                '$lookup': {
                    'from': 'verifications',
                    'localField': 'verification_id',
                    'foreignField': '_id',
                    'as': 'verification'
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'customer_id',
                    'foreignField': '_id',
                    'as': 'customer'  
                }
            },
            {'$sort': {'created_at': -1}},
            {'$skip': offset},
            {'$limit': limit}
        ]
        
        reports = list(db.counterfeit_reports.aggregate(pipeline))
        
        # Format response
        counterfeit_reports = []
        for report in reports:
            verification = report.get('verification', [{}])[0] if report.get('verification') else {}
            customer = report.get('customer', [{}])[0] if report.get('customer') else {}
            
            report_entry = {
                'report_id': str(report['_id']),
                'verification_id': str(report['verification_id']) if report.get('verification_id') else None,
                'serial_number': report['serial_number'],
                'product_name': report.get('product_name', 'Unknown Product'),
                'device_category': report.get('device_category', 'Unknown'),
                'report_status': report.get('report_status', 'pending'),
                'timestamp': report['created_at'].isoformat(),
                
                # Location info (if consent given)
                'location_info': {
                    'store_name': report.get('store_name'),
                    'store_address': report.get('store_address'),
                    'city': report.get('city'),
                    'state': report.get('state'),
                    'customer_consent': report.get('customer_consent', False)
                } if report.get('customer_consent') else None,
                
                # Purchase info
                'purchase_info': {
                    'purchase_date': report['purchase_date'].isoformat() if report.get('purchase_date') else None,
                    'purchase_price': report.get('purchase_price'),
                    'additional_notes': report.get('additional_notes')
                },
                
                # Customer info (anonymized)
                'customer_id': str(report['customer_id']),
                'customer_email': customer.get('primary_email', 'Unknown'),
                
                # Verification info
                'confidence_score': verification.get('confidence_score', 0),
                'verification_method': verification.get('verification_method', 'manual')
            }
            
            counterfeit_reports.append(report_entry)
        
        return create_cors_response({
            'status': 'success',
            'data': {
                'counterfeit_reports': counterfeit_reports,
                'pagination': {
                    'total_count': total_count,
                    'limit': limit,
                    'offset': offset,
                    'has_next': offset + limit < total_count
                }
            }
        }, 200)
        
    except Exception as e:
        print(f"API counterfeit reports error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/analytics/summary', methods=['GET'])
@api_key_required
def get_manufacturer_analytics_summary():
    """Get analytics summary for integrated manufacturer platforms"""
    try:
        # Get query parameters
        time_range = request.args.get('time_range', '30d')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        manufacturer_id = request.api_manufacturer_id
        
        # Determine date range
        if start_date and end_date:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        else:
            from datetime import timedelta
            end = datetime.now(timezone.utc)
            days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
            days = days_map.get(time_range, 30)
            start = end - timedelta(days=days)
        
        db = get_db_connection()
        
        # Get verification statistics
        verification_stats = db.verifications.aggregate([
            {
                '$match': {
                    'manufacturer_id': manufacturer_id,
                    'created_at': {'$gte': start, '$lte': end}
                }
            },
            {
                '$group': {
                    '_id': None,
                    'total_verifications': {'$sum': 1},
                    'authentic_verifications': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit_verifications': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    },
                    'unique_customers': {'$addToSet': '$customer_id'},
                    'avg_response_time': {'$avg': '$response_time'},
                    'avg_confidence': {'$avg': '$confidence_score'}
                }
            }
        ])
        
        stats = list(verification_stats)
        if not stats:
            stats = [{
                'total_verifications': 0,
                'authentic_verifications': 0,
                'counterfeit_verifications': 0,
                'unique_customers': [],
                'avg_response_time': 0,
                'avg_confidence': 0
            }]
        
        stat = stats[0]
        
        # Get counterfeit report count
        counterfeit_count = db.counterfeit_reports.count_documents({
            'manufacturer_id': manufacturer_id,
            'created_at': {'$gte': start, '$lte': end}
        })
        
        # Get device breakdown
        device_breakdown = list(db.verifications.aggregate([
            {
                '$match': {
                    'manufacturer_id': manufacturer_id,
                    'created_at': {'$gte': start, '$lte': end}
                }
            },
            {
                '$group': {
                    '_id': '$device_category',
                    'count': {'$sum': 1},
                    'authentic': {'$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}},
                    'counterfeit': {'$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}}
                }
            },
            {'$sort': {'count': -1}}
        ]))
        
        # Format device breakdown
        devices = []
        for device in device_breakdown[:10]:  # Top 10 devices
            devices.append({
                'category': device['_id'] or 'Unknown',
                'total_verifications': device['count'],
                'authentic': device['authentic'],
                'counterfeit': device['counterfeit'],
                'authenticity_rate': round((device['authentic'] / device['count']) * 100, 1) if device['count'] > 0 else 0
            })
        
        # Calculate KPIs
        total_verifications = stat['total_verifications']
        authentic_verifications = stat['authentic_verifications']
        unique_customers_count = len(stat['unique_customers'])
        
        analytics_summary = {
            'time_period': {
                'start_date': start.isoformat(),
                'end_date': end.isoformat(),
                'time_range': time_range
            },
            'key_metrics': {
                'total_verifications': total_verifications,
                'authentic_verifications': authentic_verifications,
                'counterfeit_verifications': stat['counterfeit_verifications'],
                'counterfeit_reports': counterfeit_count,
                'unique_customers': unique_customers_count,
                'authenticity_rate': round((authentic_verifications / total_verifications) * 100, 1) if total_verifications > 0 else 0,
                'avg_response_time': round(stat['avg_response_time'] or 0, 2),
                'avg_confidence_score': round(stat['avg_confidence'] or 0, 1)
            },
            'device_breakdown': devices
        }
        
        return create_cors_response({
            'status': 'success',
            'data': analytics_summary
        }, 200)
        
    except Exception as e:
        print(f"Analytics summary error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

# ======================================================
# MANUFACTURER INTEGRATION MANAGEMENT ROUTES
# ======================================================

@manufacturer_bp.route('/integrations', methods=['GET'])
@token_required
def get_manufacturer_integrations(current_user_id, current_user_role):
    """Get all integrations for a manufacturer"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        db = get_db_connection()
        integrations = list(db.manufacturer_integrations.find({
            'manufacturer_id': ObjectId(current_user_id)
        }).sort('created_at', -1))
        
        # Format integrations
        integration_list = []
        for integration in integrations:
            integration_data = {
                'integration_id': str(integration['_id']),
                'integration_name': integration['integration_name'],
                'platform_type': integration['platform_type'],
                'status': integration['status'],
                'last_sync': integration.get('last_sync').isoformat() if integration.get('last_sync') else None,
                'created_at': integration['created_at'].isoformat(),
                'webhook_url': integration.get('webhook_url', ''),
                'error_message': integration.get('error_message', '')
            }
            integration_list.append(integration_data)
        
        return create_cors_response({
            'status': 'success',
            'integrations': integration_list
        }, 200)
        
    except Exception as e:
        print(f"Get integrations error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/integrations/<integration_id>/toggle', methods=['POST'])
@token_required  
def toggle_integration_status(current_user_id, current_user_role, integration_id):
    """Activate or deactivate an integration"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        db = get_db_connection()
        integration = db.manufacturer_integrations.find_one({
            '_id': ObjectId(integration_id),
            'manufacturer_id': ObjectId(current_user_id)
        })
        
        if not integration:
            return create_cors_response({'error': 'Integration not found'}, 404)
        
        # Toggle status
        new_status = 'active' if integration['status'] == 'inactive' else 'inactive'
        
        db.manufacturer_integrations.update_one(
            {'_id': ObjectId(integration_id)},
            {
                '$set': {
                    'status': new_status,
                    'updated_at': get_current_utc(),
                    'error_message': ''  # Clear any previous errors
                }
            }
        )
        
        # Also toggle associated API keys
        db.api_keys.update_many(
            {'integration_id': ObjectId(integration_id)},
            {'$set': {'status': new_status}}
        )
        
        return create_cors_response({
            'status': 'success',
            'message': f'Integration {new_status}',
            'new_status': new_status
        }, 200)
        
    except Exception as e:
        print(f"Toggle integration error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys', methods=['GET'])
@token_required
def get_manufacturer_api_keys(current_user_id, current_user_role):
    """Get all API keys for a manufacturer"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        db = get_db_connection()
        api_keys = list(db.api_keys.find({
            'manufacturer_id': ObjectId(current_user_id)
        }).sort('created_at', -1))
        
        # Format API keys (don't include actual keys)
        key_list = []
        for key in api_keys:
            key_data = {
                'key_id': str(key['_id']),
                'name': key['name'],
                'permissions': key.get('permissions', []),
                'status': key['status'],
                'created_at': key['created_at'].isoformat(),
                'last_used': key.get('last_used').isoformat() if key.get('last_used') else None,
                'integration_id': str(key['integration_id']) if key.get('integration_id') else None
            }
            key_list.append(key_data)
        
        return create_cors_response({
            'status': 'success',
            'api_keys': key_list
        }, 200)
        
    except Exception as e:
        print(f"Get API keys error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys', methods=['POST'])
@token_required
def create_manufacturer_api_key(current_user_id, current_user_role):
    """Create a new API key for a manufacturer"""
    try:
        data = request.get_json()
        
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        if user.get('verification_status') != 'verified':
            return create_cors_response({'error': 'Account must be verified first'}, 403)
        
        # Validate input
        name = data.get('name', '').strip()
        if not name:
            return create_cors_response({'error': 'API key name is required'}, 400)
        
        permissions = data.get('permissions', ['verify', 'analytics'])
        valid_permissions = ['verify', 'register_products', 'analytics', 'webhook']
        invalid_perms = [p for p in permissions if p not in valid_permissions]
        if invalid_perms:
            return create_cors_response({
                'error': f'Invalid permissions: {", ".join(invalid_perms)}'
            }, 400)
        
        # Generate API key
        api_key = secrets.token_urlsafe(32)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        db = get_db_connection()
        
        # Check if name already exists
        existing = db.api_keys.find_one({
            'manufacturer_id': ObjectId(current_user_id),
            'name': name
        })
        if existing:
            return create_cors_response({'error': 'API key name already exists'}, 400)
        
        # Create API key
        key_doc = {
            'manufacturer_id': ObjectId(current_user_id),
            'name': name,
            'key_hash': api_key_hash,
            'permissions': permissions,
            'status': 'active',
            'created_at': get_current_utc(),
            'updated_at': get_current_utc()
        }
        
        result = db.api_keys.insert_one(key_doc)
        
        return create_cors_response({
            'status': 'success',
            'message': 'API key created successfully',
            'api_key_id': str(result.inserted_id),
            'api_key': api_key,  # Only returned once
            'name': name,
            'permissions': permissions,
            'note': 'Store this API key securely. It will not be shown again.'
        }, 201)
        
    except Exception as e:
        print(f"Create API key error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)

@manufacturer_bp.route('/api-keys/<key_id>/revoke', methods=['POST'])
@token_required
def revoke_api_key(current_user_id, current_user_role, key_id):
    """Revoke an API key"""
    try:
        user = get_user_by_id(current_user_id)
        if not user or user.get('role') != 'manufacturer':
            return create_cors_response({'error': 'Unauthorized'}, 403)
        
        db = get_db_connection()
        result = db.api_keys.update_one(
            {
                '_id': ObjectId(key_id),
                'manufacturer_id': ObjectId(current_user_id)
            },
            {
                '$set': {
                    'status': 'revoked',
                    'updated_at': get_current_utc()
                }
            }
        )
        
        if result.matched_count == 0:
            return create_cors_response({'error': 'API key not found'}, 404)
        
        return create_cors_response({
            'status': 'success',
            'message': 'API key revoked successfully'
        }, 200)
        
    except Exception as e:
        print(f"Revoke API key error: {e}")
        return create_cors_response({'error': 'Internal server error'}, 500)