"""
API Key Service
Handles API key creation, validation, and revocation for manufacturers
Extracted from manufacturer_service.py
"""

import logging
import hashlib
import secrets
from datetime import datetime, timezone
from bson import ObjectId
from typing import Dict, Any, Optional

from app.config.database import get_db_connection
from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)


class ApiKeyService:
    """Handles API key creation, validation, and revocation"""
    
    def __init__(self):
        self.db = get_db_connection()
        self.max_api_keys = 5  # Default limit
    
    @staticmethod
    def create_api_key(self, manufacturer_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new API key for a manufacturer
        
        Args:
            manufacturer_id: Manufacturer ID
            data: API key configuration
            
        Returns:
            Dict with success status and API key details
        """
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'message': 'Invalid manufacturer ID'
                }
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            manufacturer = self.db.users.find_one({
                '_id': manufacturer_obj_id,
                'role': 'manufacturer'
            })
            
            if not manufacturer:
                return {
                    'success': False,
                    'message': 'Manufacturer not found'
                }
            
            # Check API key limit for verified manufacturers
            if manufacturer.get('verification_status') == 'verified':
                existing_keys = self.db.api_keys.count_documents({
                    'manufacturer_id': manufacturer_obj_id,
                    'revoked': False
                })
                
                if existing_keys >= self.max_api_keys:
                    return {
                        'success': False,
                        'message': f'Maximum number of API keys reached ({self.max_api_keys})'
                    }
            
            # Generate API key
            api_key = self._generate_api_key()
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            api_key_doc = {
                'manufacturer_id': manufacturer_obj_id,
                'name': data.get('name', 'API Key'),
                'key_hash': key_hash,
                'key_prefix': api_key[:8] + '...',
                'permissions': data.get('permissions', ['verify_products', 'register_products']),
                'created_at': datetime.now(timezone.utc),
                'last_used': None,
                'usage_count': 0,
                'revoked': False,
                'rate_limits': {
                    'requests_per_minute': 100,
                    'requests_per_hour': 1000,
                    'requests_per_day': 10000
                }
            }
            
            result = self.db.api_keys.insert_one(api_key_doc)
            
            # Notify if manufacturer is verified
            if manufacturer.get('verification_status') == 'verified':
                notification_service.notify_api_key_created(
                    manufacturer_id,
                    data.get('name', 'API Key')
                )
            
            return {
                'success': True,
                'api_key': api_key,  # Only returned once
                'key_id': str(result.inserted_id),
                'key_preview': api_key[:8],
                'name': data.get('name', 'API Key'),
                'permissions': data.get('permissions'),
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            return {
                'success': False,
                'message': 'Failed to create API key'
            }
    
    @staticmethod
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Validate an API key and return its data
        
        Args:
            api_key: API key string
            
        Returns:
            API key data if valid, None otherwise
        """
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            key_data = self.db.api_keys.find_one({
                'key_hash': key_hash,
                'revoked': False
            })
            
            if key_data:
                # Update usage stats
                self.db.api_keys.update_one(
                    {'_id': key_data['_id']},
                    {
                        '$set': {'last_used': datetime.now(timezone.utc)},
                        '$inc': {'usage_count': 1}
                    }
                )
                
                # Log API usage
                self.db.api_usage_logs.insert_one({
                    'manufacturer_id': key_data['manufacturer_id'],
                    'api_key_id': key_data['_id'],
                    'timestamp': datetime.now(timezone.utc),
                    'endpoint': 'api_validation'
                })
                
                # Get manufacturer info
                manufacturer = self.db.users.find_one({
                    '_id': key_data['manufacturer_id']
                })
                
                if manufacturer:
                    key_data['company_name'] = manufacturer.get('current_company_name')
                    key_data['manufacturer_email'] = manufacturer.get('primary_email')
                    key_data['verification_status'] = manufacturer.get('verification_status')
            
            return key_data
            
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None
    
    @staticmethod
    def revoke_api_key(self, manufacturer_id: str, key_id: str) -> Dict[str, Any]:
        """
        Revoke an API key
        
        Args:
            manufacturer_id: Manufacturer ID
            key_id: API key ID to revoke
            
        Returns:
            Dict with success status
        """
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(key_id):
                return {
                    'success': False,
                    'message': 'Invalid ID format'
                }
            
            result = self.db.api_keys.update_one(
                {
                    '_id': ObjectId(key_id),
                    'manufacturer_id': ObjectId(manufacturer_id),
                    'revoked': False
                },
                {
                    '$set': {
                        'revoked': True,
                        'revoked_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count == 0:
                return {
                    'success': False,
                    'message': 'API key not found'
                }
            
            return {
                'success': True,
                'message': 'API key revoked successfully'
            }
            
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return {
                'success': False,
                'message': 'Failed to revoke API key'
            }
    
    @staticmethod
    def get_api_keys(self, manufacturer_id: str) -> Dict[str, Any]:
        """
        Get all active API keys for a manufacturer
        
        Args:
            manufacturer_id: Manufacturer ID
            
        Returns:
            Dict with API keys list
        """
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'message': 'Invalid manufacturer ID'
                }
            
            api_keys = list(self.db.api_keys.find(
                {
                    'manufacturer_id': ObjectId(manufacturer_id),
                    'revoked': False
                },
                {
                    'name': 1,
                    'key_prefix': 1,
                    'created_at': 1,
                    'last_used': 1,
                    'permissions': 1,
                    'usage_count': 1,
                    'rate_limits': 1
                }
            ).sort('created_at', -1))
            
            # Convert ObjectIds to strings
            for key in api_keys:
                key['_id'] = str(key['_id'])
            
            return {
                'success': True,
                'api_keys': api_keys
            }
            
        except Exception as e:
            logger.error(f"Error getting API keys: {e}")
            return {
                'success': False,
                'message': 'Failed to get API keys'
            }
    
    @staticmethod
    def _generate_api_key(self, length: int = 32) -> str:
        """Generate a secure API key"""
        characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return ''.join(secrets.choice(characters) for _ in range(length))


api_key_service = ApiKeyService()