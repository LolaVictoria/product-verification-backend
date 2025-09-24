# services/profile_service.py - Updated to handle different user roles

from datetime import datetime, timezone
from bson import ObjectId
from utils.database import get_db_connection
import logging

logger = logging.getLogger(__name__)

class ProfileService:
    def __init__(self):
        pass
    
    def get_user_profile(self, user_id, user_role):
        """Get user profile based on role"""
        try:
            if user_role == 'admin':
                return self.get_admin_profile(user_id)
            elif user_role == 'manufacturer':
                return self.get_manufacturer_profile(user_id)
            elif user_role == 'customer':
                return self.get_customer_profile(user_id)
            else:
                return {'success': False, 'message': 'Invalid user role'}
                
        except Exception as e:
            logger.error(f"Error getting user profile: {e}")
            return {'success': False, 'message': 'Failed to fetch profile'}
    
    def get_admin_profile(self, user_id):
        """Get admin profile from users collection"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            admin = db.users.find_one({
                '_id': user_id,
                'role': 'admin'
            })
            
            if not admin:
                return {'success': False, 'message': 'Admin profile not found'}
            
            # Format admin profile
            profile = {
                'id': str(admin['_id']),
                'email': admin.get('email') or admin.get('primary_email'),
                'name': admin.get('name'),
                'username': admin.get('username'),
                'role': 'admin',
                'is_active': admin.get('is_active', True),
                'verification_status': admin.get('verification_status'),
                'created_at': admin.get('created_at'),
                'last_login': admin.get('last_login'),
                'is_auth_verified': admin.get('is_auth_verified', False)
            }
            
            return {
                'success': True,
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching admin profile: {e}")
            return {'success': False, 'message': 'Failed to fetch admin profile'}
    
    def get_manufacturer_profile(self, user_id):
        """Get manufacturer profile from manufacturers collection"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Try to find manufacturer by ObjectId first
            manufacturer = db.manufacturers.find_one({'_id': user_id})
            
            # If not found, try by manufacturer_id if user_id was a string
            if not manufacturer and isinstance(user_id, ObjectId):
                manufacturer = db.manufacturers.find_one({'manufacturer_id': str(user_id)})
            
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer profile not found'}
            
            # Format manufacturer profile
            profile = {
                'id': str(manufacturer['_id']),
                'manufacturer_id': manufacturer.get('manufacturer_id'),
                'email': manufacturer.get('email') or manufacturer.get('contact_email'),
                'company_name': manufacturer.get('companyName') or manufacturer.get('company_name'),
                'name': manufacturer.get('name') or manufacturer.get('contact_name'),
                'role': 'manufacturer',
                'wallet_address': manufacturer.get('walletAddress'),
                'country': manufacturer.get('country'),
                'headquarters': manufacturer.get('headquarters'),
                'established_year': manufacturer.get('establishedYear'),
                'annual_production': manufacturer.get('annualProduction'),
                'is_verified': manufacturer.get('isVerified', False),
                'verification_status': manufacturer.get('verification_status', 'pending'),
                'verification_date': manufacturer.get('verificationDate'),
                'created_at': manufacturer.get('createdAt'),
                'is_active': manufacturer.get('is_active', True)
            }
            
            return {
                'success': True,
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching manufacturer profile: {e}")
            return {'success': False, 'message': 'Failed to fetch manufacturer profile'}
    
    def get_customer_profile(self, user_id):
        """Get customer profile from users collection"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            customer = db.users.find_one({
                '_id': user_id,
                'role': 'customer'
            })
            
            if not customer:
                return {'success': False, 'message': 'Customer profile not found'}
            
            # Format customer profile
            profile = {
                'id': str(customer['_id']),
                'email': customer.get('email') or customer.get('primary_email'),
                'name': customer.get('name'),
                'username': customer.get('username'),
                'role': 'customer',
                'is_active': customer.get('is_active', True),
                'verification_status': customer.get('verification_status'),
                'created_at': customer.get('created_at'),
                'last_login': customer.get('last_login'),
                'manufacturer_id': customer.get('manufacturer_id')  # If linked to a manufacturer
            }
            
            return {
                'success': True,
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching customer profile: {e}")
            return {'success': False, 'message': 'Failed to fetch customer profile'}
    
    def update_user_profile(self, user_id, user_role, update_data):
        """Update user profile based on role"""
        try:
            if user_role == 'admin':
                return self.update_admin_profile(user_id, update_data)
            elif user_role == 'manufacturer':
                return self.update_manufacturer_profile(user_id, update_data)
            elif user_role == 'customer':
                return self.update_customer_profile(user_id, update_data)
            else:
                return {'success': False, 'message': 'Invalid user role'}
                
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            return {'success': False, 'message': 'Failed to update profile'}
    
    def update_admin_profile(self, user_id, update_data):
        """Update admin profile"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Allowed fields for admin update
            allowed_fields = ['name', 'username']
            update_fields = {}
            
            for field in allowed_fields:
                if field in update_data:
                    update_fields[field] = update_data[field]
            
            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}
            
            # Add updated timestamp
            update_fields['updated_at'] = datetime.now(timezone.utc)
            
            # Update admin
            result = db.users.update_one(
                {'_id': user_id, 'role': 'admin'},
                {'$set': update_fields}
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'No changes made or admin not found'}
            
            # Fetch updated profile
            updated_profile = self.get_admin_profile(user_id)
            
            return {
                'success': True,
                'message': 'Admin profile updated successfully',
                'profile': updated_profile['profile']
            }
            
        except Exception as e:
            logger.error(f"Error updating admin profile: {e}")
            return {'success': False, 'message': 'Failed to update admin profile'}
    
    def update_manufacturer_profile(self, user_id, update_data):
        """Update manufacturer profile"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Allowed fields for manufacturer update
            allowed_fields = ['companyName', 'company_name', 'name', 'contact_name', 'country', 
                            'headquarters', 'establishedYear', 'annualProduction']
            update_fields = {}
            
            for field in allowed_fields:
                if field in update_data:
                    update_fields[field] = update_data[field]
            
            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}
            
            # Add updated timestamp
            update_fields['updated_at'] = datetime.now(timezone.utc)
            
            # Update manufacturer
            result = db.manufacturers.update_one(
                {'_id': user_id},
                {'$set': update_fields}
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'No changes made or manufacturer not found'}
            
            # Fetch updated profile
            updated_profile = self.get_manufacturer_profile(user_id)
            
            return {
                'success': True,
                'message': 'Manufacturer profile updated successfully',
                'profile': updated_profile['profile']
            }
            
        except Exception as e:
            logger.error(f"Error updating manufacturer profile: {e}")
            return {'success': False, 'message': 'Failed to update manufacturer profile'}
    
    def update_customer_profile(self, user_id, update_data):
        """Update customer profile"""
        try:
            db = get_db_connection()
            
            # Convert string to ObjectId if needed
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Allowed fields for customer update
            allowed_fields = ['name', 'username']
            update_fields = {}
            
            for field in allowed_fields:
                if field in update_data:
                    update_fields[field] = update_data[field]
            
            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}
            
            # Add updated timestamp
            update_fields['updated_at'] = datetime.now(timezone.utc)
            
            # Update customer
            result = db.users.update_one(
                {'_id': user_id, 'role': 'customer'},
                {'$set': update_fields}
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'No changes made or customer not found'}
            
            # Fetch updated profile
            updated_profile = self.get_customer_profile(user_id)
            
            return {
                'success': True,
                'message': 'Customer profile updated successfully',
                'profile': updated_profile['profile']
            }
            
        except Exception as e:
            logger.error(f"Error updating customer profile: {e}")
            return {'success': False, 'message': 'Failed to update customer profile'}

profile_service = ProfileService()