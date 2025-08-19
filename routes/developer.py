from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from models import ApiKey
from utils.decorators import require_role
from utils.helpers import create_error_response, create_success_response, mask_api_key
import logging

logger = logging.getLogger(__name__)

developer_bp = Blueprint('developer', __name__)

@developer_bp.route('/create-apikey', methods=['POST'])
@require_role('developer')
def create_api_key():
    """Create a new API key for the developer"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return create_error_response('No data provided')
        
        label = data.get('label', '').strip()
        
        if not label or len(label) < 3 or len(label) > 50:
            return create_error_response('Label must be between 3 and 50 characters')
        
        # Check if user already has too many API keys
        existing_keys = ApiKey.find_by_user(user_id)
        if len(existing_keys) >= 10:  # Max 10 API keys per user
            return create_error_response('Maximum number of API keys reached (10)')
        
        # Create API key
        api_key, key_id = ApiKey.create_api_key(user_id, label)
        
        return create_success_response(
            'API key created successfully',
            {
                'createApiKey': {  # Match your frontend expectation
                    'success': True,
                    'apiKey': {
                        'key': api_key  # This matches your frontend: response.data.data.api_key
                    }
                }
            },
            201
        )
        
    except Exception as e:
        logger.error(f"API key creation error: {e}")
        return create_error_response('Internal server error', 500)

@developer_bp.route('/my-apikeys', methods=['GET'])
@require_role('developer')
def get_api_keys():
    """Get all API keys for the developer"""
    try:
        user_id = get_jwt_identity()
        show_full_key = request.args.get('show_full_key', 'false').lower() == 'true'
        
        api_keys = ApiKey.find_by_user(user_id)
        
        # Convert MongoDB objects to JSON-serializable format
        serialized_keys = []
        for key_doc in api_keys:
            serialized_key = {
                '_id': str(key_doc['_id']),
                'user_id': str(key_doc['user_id']),
                'label': key_doc['label'],
                'created_at': key_doc['created_at'].isoformat() if key_doc.get('created_at') else None,
                'revoked': key_doc.get('revoked', False),
                'last_used': key_doc['last_used'].isoformat() if key_doc.get('last_used') else None,
                'usage_count': key_doc.get('usage_count', 0),
            }
            
            # Add key field based on request
            if show_full_key:
                serialized_key['key'] = key_doc.get('key', '')  # Full key from DB
                serialized_key['masked_key'] = f"pak_{mask_api_key(key_doc.get('label', ''), 4)}***"
            else:
                serialized_key['masked_key'] = f"pak_{mask_api_key(key_doc.get('label', ''), 4)}***"
        
        serialized_keys.append(serialized_key)
        
        return jsonify({
            'success': True,
            'data': {
                'api_keys': serialized_keys,
                'total': len(serialized_keys)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get API keys error: {e}")
        return create_error_response('Internal server error', 500)
    
@developer_bp.route('/apikey/<key_id>', methods=['GET'])
@require_role('developer')
def get_api_key_details(key_id):
    """Get detailed information about a specific API key"""
    try:
        from bson import ObjectId
        user_id = get_jwt_identity()
        
        api_key = ApiKey.collection.find_one({
            '_id': ObjectId(key_id),
            'user_id': ObjectId(user_id),
            'revoked': False
        }, {'key': 0})  # Don't return the actual key
        
        if not api_key:
            return create_error_response('API key not found', 404)
        
        # Get usage statistics for the last 30 days
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        usage_stats = list(ApiKey.usage_collection.aggregate([
            {
                '$match': {
                    'api_key_id': ObjectId(key_id),
                    'timestamp': {'$gte': thirty_days_ago}
                }
            },
            {
                '$group': {
                    '_id': {
                        '$dateToString': {
                            'format': '%Y-%m-%d',
                            'date': '$timestamp'
                        }
                    },
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'_id': 1}}
        ]))
        
        api_key['usage_stats_30d'] = usage_stats
        api_key['masked_key'] = f"pak_{mask_api_key(api_key.get('label', ''), 4)}***"
        
        return jsonify({'api_key': api_key}), 200
        
    except Exception as e:
        logger.error(f"Get API key details error: {e}")
        return create_error_response('Internal server error', 500)

@developer_bp.route('/revoke-apikey/<key_id>', methods=['DELETE'])
@require_role('developer')
def revoke_api_key(key_id):
    """Revoke an API key"""
    try:
        user_id = get_jwt_identity()
        
        result = ApiKey.revoke_key(key_id, user_id)
        
        if result.modified_count == 0:
            return create_error_response('API key not found', 404)
        
        return create_success_response('API key revoked successfully')
        
    except Exception as e:
        logger.error(f"API key revocation error: {e}")
        return create_error_response('Internal server error', 500)

@developer_bp.route('/regenerate-apikey/<key_id>', methods=['POST'])
@require_role('developer')
def regenerate_api_key(key_id):
    """Regenerate an API key (revoke old, create new with same label)"""
    try:
        from bson import ObjectId
        user_id = get_jwt_identity()
        
        # Find existing key
        existing_key = ApiKey.collection.find_one({
            '_id': ObjectId(key_id),
            'user_id': ObjectId(user_id),
            'revoked': False
        })
        
        if not existing_key:
            return create_error_response('API key not found', 404)
        
        # Revoke old key
        ApiKey.revoke_key(key_id, user_id)
        
        # Create new key with same label
        new_api_key, new_key_id = ApiKey.create_api_key(user_id, existing_key['label'])
        
        return create_success_response(
            'API key regenerated successfully',
            {
                'api_key': new_api_key,
                'key_id': str(new_key_id),
                'label': existing_key['label'],
                'warning': 'Save this new API key securely. The old key has been revoked.'
            }
        )
        
    except Exception as e:
        logger.error(f"API key regeneration error: {e}")
        return create_error_response('Internal server error', 500)

@developer_bp.route('/usage-analytics', methods=['GET'])
@require_role('developer')
def get_usage_analytics():
    """Get usage analytics for all developer's API keys"""
    try:
        from bson import ObjectId
        from datetime import datetime, timedelta
        
        user_id = get_jwt_identity()
        
        # Get date range (default last 30 days)
        days = int(request.args.get('days', 30))
        if days > 365:  # Max 1 year
            days = 365
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get user's API keys
        api_keys = ApiKey.find_by_user(user_id)
        key_ids = [key['_id'] for key in api_keys]
        
        if not key_ids:
            return jsonify({
                'total_requests': 0,
                'daily_usage': [],
                'endpoint_usage': []
            }), 200
        
        # Daily usage aggregation
        daily_usage = list(ApiKey.usage_collection.aggregate([
            {
                '$match': {
                    'api_key_id': {'$in': key_ids},
                    'timestamp': {'$gte': start_date}
                }
            },
            {
                '$group': {
                    '_id': {
                        '$dateToString': {
                            'format': '%Y-%m-%d',
                            'date': '$timestamp'
                        }
                    },
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'_id': 1}}
        ]))
        
        # Endpoint usage aggregation
        endpoint_usage = list(ApiKey.usage_collection.aggregate([
            {
                '$match': {
                    'api_key_id': {'$in': key_ids},
                    'timestamp': {'$gte': start_date}
                }
            },
            {
                '$group': {
                    '_id': '$endpoint',
                    'count': {'$sum': 1}
                }
            },
            {'$sort': {'count': -1}}
        ]))
        
        total_requests = sum([day['count'] for day in daily_usage])
        
        return jsonify({
            'total_requests': total_requests,
            'daily_usage': daily_usage,
            'endpoint_usage': endpoint_usage,
            'period_days': days
        }), 200
        
    except Exception as e:
        logger.error(f"Usage analytics error: {e}")
        return create_error_response('Internal server error', 500)