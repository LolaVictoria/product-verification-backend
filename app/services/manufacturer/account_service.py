"""
Manufacturer Account Service
Handles manufacturer account creation, verification, and management
Extracted from manufacturer_service.py
"""

import logging
from datetime import datetime, timezone
from bson import ObjectId
from typing import Dict, Any

from app.config.database import get_db_connection
from app.validators.manufacturer_validator import ManufacturerValidator
from app.services.notification_service import notification_service
from app.services.webhook_service import webhook_service

logger = logging.getLogger(__name__)


class ManufacturerAccountService:
    """Handles manufacturer account creation and management"""
    
    def __init__(self):
        self.db = get_db_connection()
        self.validator = ManufacturerValidator()
    
    @staticmethod
    def create_manufacturer(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new manufacturer account
        
        Args:
            user_data: Manufacturer registration data
            
        Returns:
            Dict with success status and manufacturer_id
        """
        try:
            # Validate manufacturer data
            validation_result = self.validator.validate_manufacturer_data(user_data)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': 'Validation failed',
                    'errors': validation_result['errors']
                }
            
            email = user_data.get('email').lower().strip()
            company_name = user_data.get('company_name').strip()
            
            # Check if manufacturer already exists
            existing = self.db.users.find_one({
                'role': 'manufacturer',
                '$or': [
                    {'primary_email': email},
                    {'emails.email': email}
                ]
            })
            
            if existing:
                return {
                    'success': False,
                    'error': 'Manufacturer already exists'
                }
            
            # Check if company name is already taken
            existing_company = self.db.users.find_one({
                'current_company_name': company_name,
                'role': 'manufacturer'
            })
            
            if existing_company:
                return {
                    'success': False,
                    'error': 'A manufacturer with this company name already exists'
                }
            
            # Create manufacturer document
            manufacturer_doc = {
                'name': user_data.get('name'),
                'role': 'manufacturer',
                'primary_email': email,
                'emails': [{'email': email, 'is_primary': True, 'verified': False}],
                'current_company_name': company_name,
                'company_names': [{'name': company_name, 'is_current': True}],
                'wallet_addresses': [
                    {'address': user_data.get('wallet_address'), 'is_primary': True, 'verified': False}
                ] if user_data.get('wallet_address') else [],
                'verification_status': 'pending',
                'account_status': 'active',
                'registration_date': datetime.now(timezone.utc),
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            # Insert manufacturer
            result = self.db.users.insert_one(manufacturer_doc)
            manufacturer_id = str(result.inserted_id)
            
            # Create default API key
            from app.services.manufacturer.api_key_service import api_key_service
            default_key_result = api_key_service.create_api_key(manufacturer_id, {
                'name': 'Default API Key',
                'permissions': ['verify_products', 'register_products']
            })
            
            # Notify via webhook
            webhook_service.process_manufacturer_notification({
                'type': 'manufacturer_created',
                'manufacturer_id': manufacturer_id,
                'email': email,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            return {
                'success': True,
                'manufacturer_id': manufacturer_id,
                'message': 'Manufacturer created successfully',
                'default_api_key': default_key_result.get('api_key') if default_key_result.get('success') else None
            }
            
        except Exception as e:
            logger.error(f"Error creating manufacturer: {e}")
            return {
                'success': False,
                'error': 'Failed to create manufacturer'
            }
    
    @staticmethod
    def get_manufacturer_by_id(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get manufacturer by ID"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return None
            
            manufacturer = self.db.users.find_one({
                '_id': ObjectId(manufacturer_id),
                'role': 'manufacturer'
            })
            
            return manufacturer
            
        except Exception as e:
            logger.error(f"Error getting manufacturer: {e}")
            return None
    
    @staticmethod
    def update_manufacturer(self, manufacturer_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            # Allowed fields for update
            allowed_fields = [
                'name', 'company_name', 'website', 'phone', 
                'address', 'country', 'industry', 'company_size'
            ]
            
            update_fields = {}
            for field in allowed_fields:
                if field in update_data:
                    if field == 'company_name':
                        update_fields['current_company_name'] = update_data[field]
                    else:
                        update_fields[field] = update_data[field]
            
            if not update_fields:
                return {
                    'success': False,
                    'error': 'No valid fields to update'
                }
            
            update_fields['updated_at'] = datetime.now(timezone.utc)
            
            result = self.db.users.update_one(
                {'_id': ObjectId(manufacturer_id), 'role': 'manufacturer'},
                {'$set': update_fields}
            )
            
            if result.matched_count == 0:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            return {
                'success': True,
                'message': 'Manufacturer updated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error updating manufacturer: {e}")
            return {
                'success': False,
                'error': 'Failed to update manufacturer'
            }
    
    @staticmethod
    def verify_manufacturer(self, manufacturer_id: str, admin_user_id: str) -> Dict[str, Any]:
        """Verify manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            result = self.db.users.update_one(
                {'_id': ObjectId(manufacturer_id), 'role': 'manufacturer'},
                {
                    '$set': {
                        'verification_status': 'verified',
                        'verified_at': datetime.now(timezone.utc),
                        'verified_by': ObjectId(admin_user_id),
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count == 0:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            # Send notification
            notification_service.notify_manufacturer_verification(manufacturer_id, 'verified')
            
            return {
                'success': True,
                'message': 'Manufacturer verified successfully'
            }
            
        except Exception as e:
            logger.error(f"Error verifying manufacturer: {e}")
            return {
                'success': False,
                'error': 'Failed to verify manufacturer'
            }
    
    @staticmethod
    def suspend_manufacturer(self, manufacturer_id: str, admin_user_id: str, reason: str) -> Dict[str, Any]:
        """Suspend manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            result = self.db.users.update_one(
                {'_id': ObjectId(manufacturer_id), 'role': 'manufacturer'},
                {
                    '$set': {
                        'account_status': 'suspended',
                        'suspended_at': datetime.now(timezone.utc),
                        'suspended_by': ObjectId(admin_user_id),
                        'suspension_reason': reason,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count == 0:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            return {
                'success': True,
                'message': 'Manufacturer suspended successfully'
            }
            
        except Exception as e:
            logger.error(f"Error suspending manufacturer: {e}")
            return {
                'success': False,
                'error': 'Failed to suspend manufacturer'
            }
    
    @staticmethod
    def activate_manufacturer(self, manufacturer_id: str, admin_user_id: str) -> Dict[str, Any]:
        """Activate suspended manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            result = self.db.users.update_one(
                {'_id': ObjectId(manufacturer_id), 'role': 'manufacturer'},
                {
                    '$set': {
                        'account_status': 'active',
                        'activated_at': datetime.now(timezone.utc),
                        'activated_by': ObjectId(admin_user_id),
                        'updated_at': datetime.now(timezone.utc)
                    },
                    '$unset': {
                        'suspended_at': '',
                        'suspended_by': '',
                        'suspension_reason': ''
                    }
                }
            )
            
            if result.matched_count == 0:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            return {
                'success': True,
                'message': 'Manufacturer activated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error activating manufacturer: {e}")
            return {
                'success': False,
                'error': 'Failed to activate manufacturer'
            }



account_service = ManufacturerAccountService()