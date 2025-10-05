"""
Access Control Service
Handles business authorization logic and resource access validation
Moved from middleware/auth_middleware.py
"""

import logging
from typing import Dict, Any, Optional
from bson import ObjectId

from app.config.database import get_db_connection

logger = logging.getLogger(__name__)


class AccessControlService:
    """Handles authorization and access control business logic"""
    
    def __init__(self):
        self.db = get_db_connection()
    
    def validate_manufacturer_access(self, user_id: str, user_role: str = None, 
                                    manufacturer_id: str = None) -> Dict[str, Any]:
        """
        Validate that a user has access to manufacturer resources
        
        Args:
            user_id: The user's ID from JWT token
            user_role: The user's role from JWT token
            manufacturer_id: Optional specific manufacturer ID to check access for
            
        Returns:
            Dict with 'valid' (bool), 'manufacturer_id' (str), 'message' (str)
        """
        try:
            if not ObjectId.is_valid(user_id):
                return {
                    'valid': False,
                    'manufacturer_id': None,
                    'message': 'Invalid user ID'
                }
            
            # If no role provided, get user info
            if not user_role:
                user = self.db.users.find_one({'_id': ObjectId(user_id)})
                if not user:
                    return {
                        'valid': False,
                        'manufacturer_id': None,
                        'message': 'User not found'
                    }
                user_role = user.get('role')
            
            # Admin users have access to all manufacturers
            if user_role == 'admin':
                return {
                    'valid': True,
                    'manufacturer_id': manufacturer_id,
                    'message': 'Admin access granted',
                    'is_admin': True
                }
            
            # For manufacturer users, verify they belong to the manufacturer
            if user_role == 'manufacturer':
                # Find the manufacturer record associated with this user
                manufacturer = self.db.users.find_one({
                    '_id': ObjectId(user_id),
                    'role': 'manufacturer'
                })
                
                if not manufacturer:
                    return {
                        'valid': False,
                        'manufacturer_id': None,
                        'message': 'Manufacturer account not found'
                    }
                
                user_manufacturer_id = str(manufacturer['_id'])
                
                # If specific manufacturer_id requested, verify access
                if manufacturer_id:
                    if user_manufacturer_id != str(manufacturer_id):
                        return {
                            'valid': False,
                            'manufacturer_id': user_manufacturer_id,
                            'message': 'Access denied to this manufacturer'
                        }
                
                # Verify the manufacturer is active
                if manufacturer.get('account_status') == 'suspended':
                    return {
                        'valid': False,
                        'manufacturer_id': user_manufacturer_id,
                        'message': 'Manufacturer account is suspended'
                    }
                
                if manufacturer.get('verification_status') not in ['verified', 'pending']:
                    return {
                        'valid': False,
                        'manufacturer_id': user_manufacturer_id,
                        'message': 'Manufacturer not verified'
                    }
                
                return {
                    'valid': True,
                    'manufacturer_id': user_manufacturer_id,
                    'message': 'Manufacturer access granted',
                    'is_admin': False
                }
            
            # Other roles don't have manufacturer access
            return {
                'valid': False,
                'manufacturer_id': None,
                'message': f'Role {user_role} does not have manufacturer access'
            }
            
        except Exception as e:
            logger.error(f"Error validating manufacturer access: {e}")
            return {
                'valid': False,
                'manufacturer_id': None,
                'message': 'Error validating manufacturer access'
            }
    
    def can_access_product(self, user_id: str, user_role: str, product_id: str) -> Dict[str, Any]:
        """
        Check if user can access a specific product
        
        Args:
            user_id: User ID
            user_role: User role
            product_id: Product ID to check
            
        Returns:
            Dict with access status
        """
        try:
            if not ObjectId.is_valid(product_id):
                return {
                    'valid': False,
                    'message': 'Invalid product ID'
                }
            
            product = self.db.products.find_one({'_id': ObjectId(product_id)})
            
            if not product:
                return {
                    'valid': False,
                    'message': 'Product not found'
                }
            
            # Admins can access all products
            if user_role == 'admin':
                return {
                    'valid': True,
                    'message': 'Admin access granted'
                }
            
            # Manufacturers can only access their own products
            if user_role == 'manufacturer':
                product_manufacturer_id = str(product.get('manufacturer_id'))
                
                if product_manufacturer_id != user_id:
                    return {
                        'valid': False,
                        'message': 'Access denied: not your product'
                    }
                
                return {
                    'valid': True,
                    'message': 'Product access granted'
                }
            
            # Customers can view products but not modify
            if user_role == 'customer':
                return {
                    'valid': True,
                    'read_only': True,
                    'message': 'Read-only access granted'
                }
            
            return {
                'valid': False,
                'message': 'Insufficient permissions'
            }
            
        except Exception as e:
            logger.error(f"Error checking product access: {e}")
            return {
                'valid': False,
                'message': 'Error checking product access'
            }
    
    def can_access_api_key(self, user_id: str, user_role: str, api_key_id: str) -> Dict[str, Any]:
        """
        Check if user can access/modify an API key
        
        Args:
            user_id: User ID
            user_role: User role
            api_key_id: API key ID to check
            
        Returns:
            Dict with access status
        """
        try:
            if not ObjectId.is_valid(api_key_id):
                return {
                    'valid': False,
                    'message': 'Invalid API key ID'
                }
            
            api_key = self.db.api_keys.find_one({'_id': ObjectId(api_key_id)})
            
            if not api_key:
                return {
                    'valid': False,
                    'message': 'API key not found'
                }
            
            # Admins can access all API keys
            if user_role == 'admin':
                return {
                    'valid': True,
                    'message': 'Admin access granted'
                }
            
            # Manufacturers can only access their own API keys
            if user_role == 'manufacturer':
                api_key_manufacturer_id = str(api_key.get('manufacturer_id'))
                
                if api_key_manufacturer_id != user_id:
                    return {
                        'valid': False,
                        'message': 'Access denied: not your API key'
                    }
                
                return {
                    'valid': True,
                    'message': 'API key access granted'
                }
            
            return {
                'valid': False,
                'message': 'Insufficient permissions'
            }
            
        except Exception as e:
            logger.error(f"Error checking API key access: {e}")
            return {
                'valid': False,
                'message': 'Error checking API key access'
            }
    
    def can_access_analytics(self, user_id: str, user_role: str, 
                            target_manufacturer_id: str) -> Dict[str, Any]:
        """
        Check if user can access analytics for a manufacturer
        
        Args:
            user_id: User ID
            user_role: User role
            target_manufacturer_id: Manufacturer ID whose analytics to access
            
        Returns:
            Dict with access status
        """
        try:
            # Admins can access all analytics
            if user_role == 'admin':
                return {
                    'valid': True,
                    'message': 'Admin access granted'
                }
            
            # Manufacturers can only access their own analytics
            if user_role == 'manufacturer':
                if user_id != target_manufacturer_id:
                    return {
                        'valid': False,
                        'message': 'Access denied: can only view your own analytics'
                    }
                
                return {
                    'valid': True,
                    'message': 'Analytics access granted'
                }
            
            return {
                'valid': False,
                'message': 'Insufficient permissions'
            }
            
        except Exception as e:
            logger.error(f"Error checking analytics access: {e}")
            return {
                'valid': False,
                'message': 'Error checking analytics access'
            }
    
    def can_modify_user(self, actor_user_id: str, actor_role: str, 
                       target_user_id: str) -> Dict[str, Any]:
        """
        Check if user can modify another user's account
        
        Args:
            actor_user_id: User attempting the action
            actor_role: Role of user attempting action
            target_user_id: User being modified
            
        Returns:
            Dict with access status
        """
        try:
            # Users can always modify their own account
            if actor_user_id == target_user_id:
                return {
                    'valid': True,
                    'message': 'Self-modification allowed'
                }
            
            # Admins can modify any user
            if actor_role == 'admin':
                return {
                    'valid': True,
                    'message': 'Admin modification allowed'
                }
            
            return {
                'valid': False,
                'message': 'Cannot modify other users'
            }
            
        except Exception as e:
            logger.error(f"Error checking user modification access: {e}")
            return {
                'valid': False,
                'message': 'Error checking modification access'
            }
    
    def can_access_billing(self, user_id: str, user_role: str, 
                          target_manufacturer_id: str) -> Dict[str, Any]:
        """
        Check if user can access billing information
        
        Args:
            user_id: User ID
            user_role: User role
            target_manufacturer_id: Manufacturer ID whose billing to access
            
        Returns:
            Dict with access status
        """
        try:
            # Admins can access all billing
            if user_role == 'admin':
                return {
                    'valid': True,
                    'message': 'Admin access granted'
                }
            
            # Manufacturers can only access their own billing
            if user_role == 'manufacturer':
                if user_id != target_manufacturer_id:
                    return {
                        'valid': False,
                        'message': 'Access denied: can only view your own billing'
                    }
                
                return {
                    'valid': True,
                    'message': 'Billing access granted'
                }
            
            return {
                'valid': False,
                'message': 'Insufficient permissions'
            }
            
        except Exception as e:
            logger.error(f"Error checking billing access: {e}")
            return {
                'valid': False,
                'message': 'Error checking billing access'
            }
    
    def has_feature_access(self, user_id: str, feature_name: str) -> bool:
        """
        Check if user has access to a specific feature based on subscription
        
        Args:
            user_id: User ID
            feature_name: Feature to check
            
        Returns:
            bool: True if has access, False otherwise
        """
        try:
            from app.services.billing.subscription_service import subscription_service
            return subscription_service.can_access_feature(user_id, feature_name)
        except Exception as e:
            logger.error(f"Error checking feature access: {e}")
            return False
    
    def check_rate_limit_access(self, user_id: str, user_role: str) -> Dict[str, Any]:
        """
        Get rate limit information for user
        
        Args:
            user_id: User ID
            user_role: User role
            
        Returns:
            Dict with rate limit info
        """
        try:
            if user_role == 'admin':
                return {
                    'rate_limits': {
                        'requests_per_minute': -1,  # Unlimited
                        'requests_per_hour': -1,
                        'requests_per_day': -1
                    }
                }
            
            # Get subscription limits for manufacturers
            if user_role == 'manufacturer':
                from app.services.billing.subscription_service import subscription_service
                subscription = subscription_service.get_subscription_status(user_id)
                
                if subscription['success']:
                    return {
                        'rate_limits': subscription['subscription']['limits']
                    }
            
            # Default limits for other roles
            return {
                'rate_limits': {
                    'requests_per_minute': 10,
                    'requests_per_hour': 100,
                    'requests_per_day': 1000
                }
            }
            
        except Exception as e:
            logger.error(f"Error checking rate limit access: {e}")
            return {
                'rate_limits': {
                    'requests_per_minute': 10,
                    'requests_per_hour': 100,
                    'requests_per_day': 1000
                }
            }


access_control_service = AccessControlService()