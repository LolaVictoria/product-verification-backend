"""
Profile service for user profile management
"""
import logging
from datetime import datetime, timezone
from bson import ObjectId
from typing import Dict, Any, Optional

from utils.database import get_db_connection
from utils.validators import validate_manufacturer_data

logger = logging.getLogger(__name__)

class ProfileService:
    def __init__(self):
        self.db = get_db_connection()
    
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """
        Get user profile by user ID
        
        Args:
            user_id (str): User ID
            
        Returns:
            Dict[str, Any]: Profile data with success status
        """
        try:
            if not ObjectId.is_valid(user_id):
                return {'success': False, 'message': 'Invalid user ID format'}
            
            user_obj_id = ObjectId(user_id)
            
            # Find user in database
            user = self.db.users.find_one({'_id': user_obj_id})
            
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            # Build profile response based on user role
            profile = self._build_profile_response(user)
            
            return {
                'success': True,
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error getting user profile: {e}")
            return {'success': False, 'message': 'Failed to get user profile'}
    
    def update_user_profile(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user profile
        
        Args:
            user_id (str): User ID
            update_data (Dict[str, Any]): Data to update
            
        Returns:
            Dict[str, Any]: Update result with success status
        """
        try:
            if not ObjectId.is_valid(user_id):
                return {'success': False, 'message': 'Invalid user ID format'}
            
            user_obj_id = ObjectId(user_id)
            
            # Check if user exists
            user = self.db.users.find_one({'_id': user_obj_id})
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            # Validate update data based on user role
            validation_result = self._validate_profile_update(user['role'], update_data)
            if not validation_result['valid']:
                return {'success': False, 'message': validation_result['errors']}
            
            # Prepare update document
            update_doc = self._prepare_update_document(user['role'], update_data)
            update_doc['updated_at'] = datetime.now(timezone.utc)
            
            # Update user in database
            result = self.db.users.update_one(
                {'_id': user_obj_id},
                {'$set': update_doc}
            )
            
            if result.matched_count == 0:
                return {'success': False, 'message': 'User not found'}
            
            # Get updated profile
            updated_user = self.db.users.find_one({'_id': user_obj_id})
            profile = self._build_profile_response(updated_user)
            
            return {
                'success': True,
                'message': 'Profile updated successfully',
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            return {'success': False, 'message': 'Failed to update user profile'}
    
    def _build_profile_response(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build profile response based on user role
        
        Args:
            user (Dict[str, Any]): User document from database
            
        Returns:
            Dict[str, Any]: Formatted profile data
        """
        # Base profile data
        profile = {
            'id': str(user['_id']),
            'role': user.get('role'),
            'primary_email': user.get('primary_email'),
            'name': user.get('name'),
            'account_status': user.get('account_status', 'active'),
            'created_at': user.get('created_at'),
            'updated_at': user.get('updated_at')
        }
        
        # Role-specific profile data
        if user.get('role') == 'manufacturer':
            profile.update({
                'current_company_name': user.get('current_company_name'),
                'company_names': user.get('company_names', []),
                'verification_status': user.get('verification_status', 'pending'),
                'wallet_addresses': user.get('wallet_addresses', []),
                'emails': user.get('emails', []),
                'registration_date': user.get('registration_date'),
                'business_info': {
                    'business_type': user.get('business_type'),
                    'business_registration_number': user.get('business_registration_number'),
                    'tax_id': user.get('tax_id'),
                    'address': user.get('business_address'),
                    'phone': user.get('business_phone'),
                    'website': user.get('website')
                },
                'contact_info': {
                    'contact_person': user.get('contact_person'),
                    'contact_phone': user.get('contact_phone'),
                    'support_email': user.get('support_email')
                }
            })
        
        elif user.get('role') == 'customer':
            profile.update({
                'first_name': user.get('first_name'),
                'last_name': user.get('last_name'),
                'phone': user.get('phone'),
                'address': user.get('address'),
                'date_of_birth': user.get('date_of_birth'),
                'preferences': user.get('preferences', {})
            })
        
        elif user.get('role') == 'admin':
            profile.update({
                'admin_level': user.get('admin_level', 'basic'),
                'permissions': user.get('permissions', []),
                'last_login': user.get('last_login')
            })
        
        return profile
    
    def _validate_profile_update(self, user_role: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate profile update data based on user role
        
        Args:
            user_role (str): User role
            update_data (Dict[str, Any]): Data to validate
            
        Returns:
            Dict[str, Any]: Validation result
        """
        errors = []
        
        # Common validations
        if 'name' in update_data:
            name = update_data['name']
            if name and (len(name) < 2 or len(name) > 100):
                errors.append("Name must be between 2 and 100 characters")
        
        if 'phone' in update_data:
            phone = update_data['phone']
            if phone and len(phone) > 20:
                errors.append("Phone number cannot exceed 20 characters")
        
        # Role-specific validations
        if user_role == 'manufacturer':
            if 'current_company_name' in update_data:
                company_name = update_data['current_company_name']
                if company_name and (len(company_name) < 2 or len(company_name) > 200):
                    errors.append("Company name must be between 2 and 200 characters")
            
            if 'wallet_address' in update_data:
                import re
                wallet_address = update_data['wallet_address']
                if wallet_address and not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
                    errors.append("Invalid wallet address format")
            
            if 'website' in update_data:
                website = update_data['website']
                if website and not website.startswith(('http://', 'https://')):
                    errors.append("Website must start with http:// or https://")
        
        elif user_role == 'customer':
            if 'first_name' in update_data:
                first_name = update_data['first_name']
                if first_name and (len(first_name) < 1 or len(first_name) > 50):
                    errors.append("First name must be between 1 and 50 characters")
            
            if 'last_name' in update_data:
                last_name = update_data['last_name']
                if last_name and (len(last_name) < 1 or len(last_name) > 50):
                    errors.append("Last name must be between 1 and 50 characters")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    def _prepare_update_document(self, user_role: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare update document for database
        
        Args:
            user_role (str): User role
            update_data (Dict[str, Any]): Update data
            
        Returns:
            Dict[str, Any]: Prepared update document
        """
        # Fields that are safe to update directly
        safe_fields = {
            'manufacturer': [
                'name', 'current_company_name', 'business_type', 
                'business_registration_number', 'tax_id', 'business_address',
                'business_phone', 'website', 'contact_person', 
                'contact_phone', 'support_email'
            ],
            'customer': [
                'name', 'first_name', 'last_name', 'phone', 
                'address', 'date_of_birth', 'preferences'
            ],
            'admin': [
                'name', 'phone'
            ]
        }
        
        allowed_fields = safe_fields.get(user_role, [])
        update_doc = {}
        
        for field in allowed_fields:
            if field in update_data:
                update_doc[field] = update_data[field]
        
        # Handle special cases
        if user_role == 'manufacturer':
            # Handle wallet address updates
            if 'wallet_address' in update_data:
                wallet_address = update_data['wallet_address']
                # Add new wallet address to the list
                update_doc['$push'] = {
                    'wallet_addresses': {
                        'address': wallet_address,
                        'is_primary': True,
                        'verified': False,
                        'added_at': datetime.now(timezone.utc)
                    }
                }
            
            # Handle company name history
            if 'current_company_name' in update_data:
                company_name = update_data['current_company_name']
                update_doc['$push'] = update_doc.get('$push', {})
                update_doc['$push']['company_names'] = {
                    'name': company_name,
                    'is_current': True,
                    'changed_at': datetime.now(timezone.utc)
                }
        
        return update_doc
    
    def get_profile_completion_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get profile completion status for user
        
        Args:
            user_id (str): User ID
            
        Returns:
            Dict[str, Any]: Profile completion status
        """
        try:
            if not ObjectId.is_valid(user_id):
                return {'success': False, 'message': 'Invalid user ID format'}
            
            user_obj_id = ObjectId(user_id)
            user = self.db.users.find_one({'_id': user_obj_id})
            
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            completion_data = self._calculate_profile_completion(user)
            
            return {
                'success': True,
                'completion': completion_data
            }
            
        except Exception as e:
            logger.error(f"Error getting profile completion status: {e}")
            return {'success': False, 'message': 'Failed to get completion status'}
    
    def _calculate_profile_completion(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate profile completion percentage
        
        Args:
            user (Dict[str, Any]): User document
            
        Returns:
            Dict[str, Any]: Completion data
        """
        role = user.get('role')
        
        if role == 'manufacturer':
            required_fields = [
                'name', 'primary_email', 'current_company_name',
                'business_type', 'business_phone', 'wallet_addresses'
            ]
            optional_fields = [
                'business_registration_number', 'tax_id', 'business_address',
                'website', 'contact_person', 'support_email'
            ]
        elif role == 'customer':
            required_fields = [
                'name', 'primary_email', 'first_name', 'last_name'
            ]
            optional_fields = [
                'phone', 'address', 'date_of_birth'
            ]
        else:
            required_fields = ['name', 'primary_email']
            optional_fields = ['phone']
        
        # Calculate completion
        completed_required = sum(1 for field in required_fields if user.get(field))
        completed_optional = sum(1 for field in optional_fields if user.get(field))
        
        total_fields = len(required_fields) + len(optional_fields)
        completed_fields = completed_required + completed_optional
        
        completion_percentage = (completed_fields / total_fields * 100) if total_fields > 0 else 100
        
        missing_required = [field for field in required_fields if not user.get(field)]
        missing_optional = [field for field in optional_fields if not user.get(field)]
        
        return {
            'percentage': round(completion_percentage, 1),
            'completed_fields': completed_fields,
            'total_fields': total_fields,
            'required_completed': completed_required,
            'required_total': len(required_fields),
            'missing_required': missing_required,
            'missing_optional': missing_optional,
            'is_complete': len(missing_required) == 0
        }


profile_service = ProfileService()