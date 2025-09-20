# services/manufacturer_service.py
import logging
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, Any, List, Optional

from utils.database import get_db_connection
from utils.validators import validate_product_data, validate_manufacturer_data, validate_ownership_transfer
from utils.helpers import format_product_response, generate_api_key
from services.notification_service import notification_service
from services.blockchain_service import blockchain_service

logger = logging.getLogger(__name__)

class ManufacturerService:
    def __init__(self):
        self.db = get_db_connection()
    
    def create_manufacturer(self, user_data):
        """Create new manufacturer"""
        try:
            # Validate manufacturer data
            validation_result = validate_manufacturer_data(user_data)
            if not validation_result['valid']:
                return {'success': False, 'error': validation_result['errors']}
            
            # Check if manufacturer already exists
            existing = self.db.users.find_one({
                'role': 'manufacturer',
                '$or': [
                    {'primary_email': user_data.get('email')},
                    {'wallet_addresses.address': user_data.get('wallet_address')}
                ]
            })
            
            if existing:
                return {'success': False, 'error': 'Manufacturer already exists'}
            
            # Create manufacturer document
            manufacturer_doc = {
                'name': user_data.get('name'),
                'role': 'manufacturer',
                'primary_email': user_data.get('email'),
                'emails': [{'email': user_data.get('email'), 'is_primary': True, 'verified': False}],
                'current_company_name': user_data.get('company_name'),
                'company_names': [{'name': user_data.get('company_name'), 'is_current': True}],
                'wallet_addresses': [{'address': user_data.get('wallet_address'), 'is_primary': True, 'verified': False}],
                'verification_status': 'pending',
                'account_status': 'active',
                'registration_date': datetime.now(timezone.utc),
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            result = self.db.users.insert_one(manufacturer_doc)
            manufacturer_id = str(result.inserted_id)
            
            # Create default API key
            default_key_result = self.create_api_key(manufacturer_id, {
                'name': 'Default API Key',
                'permissions': ['verify_products', 'register_products']
            })
            
            return {
                'success': True,
                'manufacturer_id': manufacturer_id,
                'message': 'Manufacturer created successfully',
                'default_api_key': default_key_result.get('data', {}).get('api_key') if default_key_result.get('success') else None
            }
            
        except Exception as e:
            logger.error(f"Error creating manufacturer: {e}")
            return {'success': False, 'error': 'Failed to create manufacturer'}
    
    def validate_api_key(self, api_key):
        """Validate API key and return key data"""
        try:
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            key_data = self.db.api_keys.find_one({
                'key_hash': api_key_hash,
                'revoked': False
            })
            
            if key_data:
                # Update usage statistics
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
                manufacturer = self.db.users.find_one({'_id': key_data['manufacturer_id']})
                
                if manufacturer:
                    key_data['company_name'] = manufacturer.get('current_company_name')
                    key_data['manufacturer_email'] = manufacturer.get('primary_email')
                    key_data['verification_status'] = manufacturer.get('verification_status')
            
            return key_data
            
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None
    
    def get_dashboard_stats(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get manufacturer dashboard statistics"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Get product statistics
            total_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id
            })
            
            verified_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'blockchain_status': 'confirmed'
            })
            
            pending_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'blockchain_status': 'pending'
            })
            
            # Get verification statistics (last 30 days)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            
            recent_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            successful_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'result': 'authentic',
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            counterfeit_detections = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'result': 'counterfeit',
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            # Get API usage statistics
            active_api_keys = self.db.api_keys.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'revoked': False
            })
            
            api_usage_30d = self.db.api_usage_logs.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            # Get recent activity
            recent_products = list(self.db.products.find(
                {'manufacturer_id': manufacturer_obj_id},
                {'serial_number': 1, 'brand': 1, 'model': 1, 'created_at': 1, 'blockchain_status': 1}
            ).sort('created_at', -1).limit(5))
            
            for product in recent_products:
                product['_id'] = str(product['_id'])
            
            return {
                'success': True,
                'data': {
                    'product_stats': {
                        'total_products': total_products,
                        'verified_products': verified_products,
                        'pending_products': pending_products,
                        'verification_rate': (verified_products / total_products * 100) if total_products > 0 else 0
                    },
                    'verification_stats': {
                        'total_verifications': recent_verifications,
                        'successful_verifications': successful_verifications,
                        'counterfeit_detections': counterfeit_detections,
                        'success_rate': (successful_verifications / recent_verifications * 100) if recent_verifications > 0 else 0
                    },
                    'api_stats': {
                        'active_api_keys': active_api_keys,
                        'api_usage_30d': api_usage_30d
                    },
                    'recent_products': recent_products,
                    'account_info': {
                        'verification_status': manufacturer.get('verification_status'),
                        'account_status': manufacturer.get('account_status'),
                        'company_name': manufacturer.get('current_company_name')
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {'success': False, 'message': 'Failed to get dashboard stats'}
    
    def get_api_keys(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get manufacturer's API keys"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            api_keys = list(self.db.api_keys.find(
                {'manufacturer_id': manufacturer_obj_id, 'revoked': False},
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
            
            for key in api_keys:
                key['_id'] = str(key['_id'])
            
            return {
                'success': True,
                'api_keys': api_keys
            }
            
        except Exception as e:
            logger.error(f"Error getting API keys: {e}")
            return {'success': False, 'message': 'Failed to get API keys'}
    
    def create_api_key(self, manufacturer_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key for manufacturer"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({
                '_id': manufacturer_obj_id,
                'role': 'manufacturer'
            })
            
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # For verified manufacturers, check API key limit
            if manufacturer.get('verification_status') == 'verified':
                existing_keys = self.db.api_keys.count_documents({
                    'manufacturer_id': manufacturer_obj_id,
                    'revoked': False
                })
                
                if existing_keys >= 5:  # Limit to 5 active API keys
                    return {'success': False, 'message': 'Maximum number of API keys reached (5)'}
            
            # Generate API key using helper function or create one
            try:
                api_key = generate_api_key()
            except:
                # Fallback if helper function doesn't exist
                api_key = f"pk_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
            
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Create API key record
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
            
            # Send notification if manufacturer is verified
            if manufacturer.get('verification_status') == 'verified':
                notification_service.notify_api_key_created(manufacturer_id, data.get('name', 'API Key'))
            
            return {
                'success': True,
                'data': {
                    'key_id': str(result.inserted_id),
                    'api_key': api_key,  # Only returned once
                    'name': data.get('name', 'API Key'),
                    'permissions': data.get('permissions', ['verify_products', 'register_products']),
                    'created_at': datetime.now(timezone.utc).isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            return {'success': False, 'message': 'Failed to create API key'}
    
    def revoke_api_key(self, manufacturer_id: str, key_id: str) -> Dict[str, Any]:
        """Revoke an API key"""
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(key_id):
                return {'success': False, 'message': 'Invalid ID format'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            key_obj_id = ObjectId(key_id)
            
            # Update API key to revoked
            result = self.db.api_keys.update_one(
                {
                    '_id': key_obj_id,
                    'manufacturer_id': manufacturer_obj_id,
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
                return {'success': False, 'message': 'API key not found'}
            
            return {
                'success': True,
                'message': 'API key revoked successfully'
            }
            
        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return {'success': False, 'message': 'Failed to revoke API key'}
    
    def register_product_via_api(self, product_data):
        """Register product via API"""
        try:
            # Validate product data
            validation_error = validate_product_data(product_data)
            if validation_error:
                return {'success': False, 'error': validation_error}
            
            # Check if product already exists
            existing = self.db.products.find_one({
                'serial_number': product_data['serial_number']
            })
            
            if existing:
                return {'success': False, 'error': 'Product already exists'}
            
            # Get manufacturer details
            manufacturer = self.db.users.find_one({
                '_id': ObjectId(product_data['manufacturer_id'])
            })
            
            if not manufacturer:
                return {'success': False, 'error': 'Manufacturer not found'}
            
            # Create product document
            product_doc = {
                'serial_number': product_data['serial_number'],
                'brand': product_data.get('brand'),
                'model': product_data.get('model'),
                'device_type': product_data.get('device_type'),
                'product_type': product_data.get('product_type', product_data.get('device_type')),
                'manufacturer_id': ObjectId(product_data['manufacturer_id']),
                'manufacturer_name': manufacturer.get('current_company_name'),
                'manufacturer_wallet': manufacturer.get('wallet_addresses', [{}])[0].get('address'),
                'registration_type': 'api',
                'blockchain_status': 'pending',
                'blockchain_verified': False,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            # Optional blockchain registration
            if product_data.get('register_on_blockchain', False):
                try:
                    blockchain_result = blockchain_service.register_device(
                        product_data['serial_number'],
                        product_doc
                    )
                    
                    if blockchain_result['success']:
                        product_doc.update({
                            'registration_type': 'blockchain_confirmed',
                            'blockchain_status': 'confirmed',
                            'blockchain_verified': True,
                            'blockchain_hash': blockchain_result['transaction_hash'],
                            'blockchain_block': blockchain_result.get('block_number'),
                            'confirmed_at': datetime.now(timezone.utc)
                        })
                except Exception as e:
                    logger.warning(f"Blockchain registration failed: {e}")
            
            result = self.db.products.insert_one(product_doc)
            
            return {
                'success': True,
                'product_id': str(result.inserted_id),
                'serial_number': product_data['serial_number'],
                'registration_type': product_doc['registration_type'],
                'blockchain_status': product_doc['blockchain_status']
            }
            
        except Exception as e:
            logger.error(f"Error registering product via API: {e}")
            return {'success': False, 'error': 'Failed to register product'}
    
    def get_manufacturer_products_api(self, manufacturer_id, page=1, limit=50):
        """Get manufacturer's products for API"""
        try:
            skip = (page - 1) * limit
            
            products = list(self.db.products.find(
                {'manufacturer_id': ObjectId(manufacturer_id)}
            ).sort('created_at', -1).skip(skip).limit(limit))
            
            total = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            formatted_products = [format_product_response(p) for p in products]
            
            return {
                'products': formatted_products,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'pages': (total + limit - 1) // limit
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer products: {e}")
            raise
    
    def get_manufacturer_analytics_api(self, manufacturer_id, time_range='7d'):
        """Get manufacturer analytics for API"""
        try:
            from utils.date_helpers import get_date_range
            start_date, end_date = get_date_range(time_range)
            
            # Product statistics
            total_products = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            recent_products = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id),
                'created_at': {'$gte': start_date}
            })
            
            # Verification statistics
            manufacturer_products = list(self.db.products.find(
                {'manufacturer_id': ObjectId(manufacturer_id)},
                {'serial_number': 1}
            ))
            
            serial_numbers = [p['serial_number'] for p in manufacturer_products]
            
            if serial_numbers:
                verifications = self.db.verification_logs.count_documents({
                    'serial_number': {'$in': serial_numbers},
                    'timestamp': {'$gte': start_date}
                })
                
                successful_verifications = self.db.verification_logs.count_documents({
                    'serial_number': {'$in': serial_numbers},
                    'result': 'authentic',
                    'timestamp': {'$gte': start_date}
                })
                
                counterfeit_detections = self.db.verification_logs.count_documents({
                    'serial_number': {'$in': serial_numbers},
                    'result': 'counterfeit',
                    'timestamp': {'$gte': start_date}
                })
            else:
                verifications = 0
                successful_verifications = 0
                counterfeit_detections = 0
            
            return {
                'time_range': time_range,
                'products': {
                    'total': total_products,
                    'recent': recent_products
                },
                'verifications': {
                    'total': verifications,
                    'successful': successful_verifications,
                    'counterfeit': counterfeit_detections,
                    'success_rate': (successful_verifications / verifications * 100) if verifications > 0 else 0
                },
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer analytics: {e}")
            raise
    
    def transfer_ownership_via_api(self, transfer_data, manufacturer_id):
        """Transfer product ownership via API"""
        try:
            # Validate transfer data
            validation_error = validate_ownership_transfer(transfer_data)
            if validation_error:
                return {'success': False, 'error': validation_error}
            
            # Check product exists and belongs to manufacturer
            product = self.db.products.find_one({
                'serial_number': transfer_data['serial_number'],
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            if not product:
                return {'success': False, 'error': 'Product not found or access denied'}
            
            # Create transfer record
            transfer_doc = {
                'serial_number': transfer_data['serial_number'],
                'product_id': str(product['_id']),
                'from_manufacturer_id': ObjectId(manufacturer_id),
                'new_owner_address': transfer_data['new_owner_address'],
                'transfer_reason': transfer_data['transfer_reason'],
                'sale_price': transfer_data.get('sale_price', 0),
                'transfer_date': datetime.now(timezone.utc),
                'status': 'completed'
            }
            
            result = self.db.ownership_transfers.insert_one(transfer_doc)
            
            # Update product current owner
            self.db.products.update_one(
                {'_id': product['_id']},
                {
                    '$set': {
                        'current_owner': transfer_data['new_owner_address'],
                        'updated_at': datetime.now(timezone.utc)
                    },
                    '$push': {
                        'ownership_history': {
                            'from_manufacturer_id': ObjectId(manufacturer_id),
                            'to_owner_address': transfer_data['new_owner_address'],
                            'transfer_date': datetime.now(timezone.utc),
                            'reason': transfer_data['transfer_reason']
                        }
                    }
                }
            )
            
            return {
                'success': True,
                'transfer_id': str(result.inserted_id)
            }
            
        except Exception as e:
            logger.error(f"Error transferring ownership: {e}")
            return {'success': False, 'error': 'Failed to transfer ownership'}


manufacturer_service = ManufacturerService()