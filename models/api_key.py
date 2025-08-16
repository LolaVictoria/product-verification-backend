from datetime import datetime
from extensions import mongo
from bson import ObjectId
import secrets

class ApiKey:
    @staticmethod
    def get_collection():
        return mongo.db.apikeys
    def get_usage_collection():
        return mongo.db.api_usage
    
    @staticmethod
    def generate_key():
        """Generate a new API key"""
        return f"pak_{secrets.token_urlsafe(32)}"
    
    @staticmethod
    def create_api_key(user_id, label):
        """Create a new API key"""
        api_key = ApiKey.generate_key()
        
        api_key_data = {
            'user_id': ObjectId(user_id),
            'key': api_key,
            'label': label,
            'created_at': datetime.utcnow(),
            'revoked': False,
            'last_used': None,
            'usage_count': 0
        }
        
        result = ApiKey.get_collection().insert_one(api_key_data)
        return api_key, result.inserted_id
    
    @staticmethod
    def find_by_key(api_key):
        """Find API key document by key value"""
        return ApiKey.get_collection().find_one({
            'key': api_key,
            'revoked': False
        })
    
    @staticmethod
    def find_by_user(user_id):
        """Find all active API keys for a user"""
        return list(ApiKey.get_collection().find(
            {'user_id': ObjectId(user_id), 'revoked': False},
            {'key': 0}  # Don't return the actual key for security
        ).sort('created_at', -1))
    
    @staticmethod
    def revoke_key(key_id, user_id):
        """Revoke an API key"""
        return ApiKey.get_collection().update_one(
            {'_id': ObjectId(key_id), 'user_id': ObjectId(user_id)},
            {'$set': {'revoked': True, 'revoked_at': datetime.utcnow()}}
        )
    
    @staticmethod
    def update_usage(key_id):
        """Update API key usage statistics"""
        ApiKey.get_collection().update_one(
            {'_id': key_id},
            {
                '$set': {'last_used': datetime.utcnow()},
                '$inc': {'usage_count': 1}
            }
        )
    
    @staticmethod
    def log_usage(key_id, user_id, endpoint, ip, user_agent):
        """Log API key usage"""
        ApiKey.get_usage_collection.insert_one({
            'api_key_id': key_id,
            'user_id': user_id,
            'endpoint': endpoint,
            'ip': ip,
            'timestamp': datetime.utcnow(),
            'user_agent': user_agent
        })