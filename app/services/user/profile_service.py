# services/profile_service.py 
from datetime import datetime, timezone
from bson import ObjectId
from app.config.database import get_db_connection
import logging

logger = logging.getLogger(__name__)

class ProfileService:
    def __init__(self):
        pass
    
    @staticmethod
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
    
    @staticmethod
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
    
    @staticmethod
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
    
    @staticmethod
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
    
    @staticmethod
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

    @staticmethod
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
            
            # Use the main formatter from utils/helpers.py
            from app.utils.formatters import format_user_response
            formatted_profile = format_user_response(admin)
            
            # Add admin-specific fields
            formatted_profile.update({
                'permissions': admin.get('permissions', []),
                'last_login': admin.get('last_login').isoformat() if admin.get('last_login') else None,
                'login_count': admin.get('login_count', 0),
                'is_super_admin': admin.get('is_super_admin', False)
            })
            
            return {
                'success': True,
                'profile': formatted_profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching admin profile: {e}")
            return {'success': False, 'message': 'Failed to fetch admin profile'}

    @staticmethod
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
                'email': manufacturer.get('contact_email') or manufacturer.get('primary_email'),
                'company_name': manufacturer.get('company_name') or manufacturer.get('current_company_name'),
                'name': manufacturer.get('contact_name') or manufacturer.get('name'),
                'role': 'manufacturer',
                'phone': manufacturer.get('phone'),
                'website': manufacturer.get('website'),
                'industry': manufacturer.get('industry'),
                'country': manufacturer.get('country'),
                'company_size': manufacturer.get('company_size'),
                'headquarters': manufacturer.get('headquarters'),
                'established_year': manufacturer.get('established_year'),
                'annual_production': manufacturer.get('annual_production'),
                
                # Wallet information
                'wallet_addresses': manufacturer.get('wallet_addresses', []),
                'primary_wallet': manufacturer.get('primary_wallet'),
                'verified_wallets': manufacturer.get('verified_wallets', []),
                
                # Status information
                'verification_status': manufacturer.get('verification_status', 'pending'),
                'account_status': manufacturer.get('account_status', 'active'),
                'subscription_status': manufacturer.get('subscription_status', 'trial'),
                'subscription_plan': manufacturer.get('subscription_plan', 'trial'),
                'is_verified': manufacturer.get('is_verified', False),
                'is_active': manufacturer.get('is_active', True),
                
                # Trial information
                'trial_starts': manufacturer.get('trial_starts').isoformat() if manufacturer.get('trial_starts') else None,
                'trial_expires': manufacturer.get('trial_expires').isoformat() if manufacturer.get('trial_expires') else None,
                
                # Integration settings
                'api_keys_count': len(manufacturer.get('api_keys', [])),
                'webhook_url': manufacturer.get('webhook_url'),
                'integration_settings': manufacturer.get('integration_settings', {}),
                
                # Timestamps
                'created_at': manufacturer.get('created_at').isoformat() if manufacturer.get('created_at') else None,
                'updated_at': manufacturer.get('updated_at').isoformat() if manufacturer.get('updated_at') else None,
                'verification_date': manufacturer.get('verification_date').isoformat() if manufacturer.get('verification_date') else None
            }
            
            return {
                'success': True,
                'profile': profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching manufacturer profile: {e}")
            return {'success': False, 'message': 'Failed to fetch manufacturer profile'}

    @staticmethod
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
            
            # Use the main formatter from utils/helpers.py
            from app.utils.formatters import format_user_response
            formatted_profile = format_user_response(customer)
            
            # Add customer-specific fields
            formatted_profile.update({
                'total_verifications': customer.get('total_verifications', 0),
                'last_verification': customer.get('last_verification').isoformat() if customer.get('last_verification') else None,
                'manufacturer_id': str(customer.get('manufacturer_id')) if customer.get('manufacturer_id') else None,
                'registration_source': customer.get('registration_source', 'direct'),
                'email_verified': customer.get('email_verified', False),
                'phone': customer.get('phone'),
                'preferences': customer.get('preferences', {}),
                'location': customer.get('location', {}),
            })
            
            return {
                'success': True,
                'profile': formatted_profile
            }
            
        except Exception as e:
            logger.error(f"Error fetching customer profile: {e}")
            return {'success': False, 'message': 'Failed to fetch customer profile'}


profile_service = ProfileService()