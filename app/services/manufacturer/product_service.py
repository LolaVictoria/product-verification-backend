# services/manufacturer/product_service.py
import logging
import secrets
import string
from datetime import datetime, timezone
from bson import ObjectId
from typing import Dict, Any
from bson import ObjectId
import pymongo
from app.config.database import get_db_connection
from app.utils.formatters import format_product_response
from app.utils.date_helpers import date_helper_utils
from app.validators.product_validator import product_validator

logger = logging.getLogger(__name__)

class ProductService:
    def __init__(self):
        self.db = get_db_connection()
    
    @staticmethod
    def generate_serial_number(self, manufacturer_prefix: str = None) -> str:
        """Generate a unique serial number"""
        if manufacturer_prefix:
            prefix = manufacturer_prefix[:3].upper()
        else:
            prefix = "PRD"
        
        # Generate random alphanumeric string
        random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        
        return f"{prefix}-{random_part}"
    
    @staticmethod
    def get_manufacturer_products(self, manufacturer_id: str, page: int = 1, limit: int = 20, filter_type: str = 'all') -> Dict[str, Any]:
        """Get manufacturer's products with pagination and filtering"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            skip = (page - 1) * limit
            
            # Build filter
            filter_dict = {'manufacturer_id': manufacturer_obj_id}
            
            if filter_type == 'verified':
                filter_dict['blockchain_status'] = 'confirmed'
            elif filter_type == 'pending':
                filter_dict['blockchain_status'] = 'pending'
            elif filter_type == 'failed':
                filter_dict['blockchain_status'] = 'failed'
            
            # Get products
            products = list(self.db.products.find(
                filter_dict,
                {
                    'serial_number': 1,
                    'brand': 1,
                    'model': 1,
                    'product_type': 1,
                    'blockchain_status': 1,
                    'created_at': 1,
                    'blockchain_hash': 1
                }
            ).sort('created_at', -1).skip(skip).limit(limit))
            
            # Get total count
            total = self.db.products.count_documents(filter_dict)
            
            # Convert ObjectIds to strings
            for product in products:
                product['_id'] = str(product['_id'])
            
            return {
                'success': True,
                'data': {
                    'products': products,
                    'total': total,
                    'page': page,
                    'limit': limit,
                    'pages': (total + limit - 1) // limit
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer products: {e}")
            return {'success': False, 'message': 'Failed to get products'}
    
    @staticmethod
    def register_product(self, manufacturer_id: str, product_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new product"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists and is verified
            manufacturer = self.db.users.find_one({
                '_id': manufacturer_obj_id,
                'role': 'manufacturer',
                'verification_status': 'verified'
            })
            
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found or not verified'}
            
            # Generate serial number if not provided
            serial_number = product_data.get('serial_number')
            if not serial_number:
                company_name = manufacturer.get('current_company_name', '')
                prefix = company_name[:3].upper() if company_name else None
                serial_number = self.generate_serial_number(prefix)
            
            # Check if serial number already exists
            existing_product = self.db.products.find_one({'serial_number': serial_number})
            if existing_product:
                return {'success': False, 'message': 'Serial number already exists'}
            
            # Create product document
            product_doc = {
                'manufacturer_id': manufacturer_obj_id,
                'serial_number': serial_number,
                'brand': product_data['brand'],
                'model': product_data['model'],
                'product_type': product_data.get('product_type', 'general'),
                'description': product_data.get('description', ''),
                'specifications': product_data.get('specifications', {}),
                'manufacturing_date': product_data.get('manufacturing_date'),
                'batch_number': product_data.get('batch_number'),
                'blockchain_status': 'pending',
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            # Insert product
            result = self.db.products.insert_one(product_doc)
            product_id = str(result.inserted_id)
            
            return {
                'success': True,
                'message': 'Product registered successfully',
                'product_id': product_id,
                'serial_number': serial_number
            }
            
        except Exception as e:
            logger.error(f"Error registering product: {e}")
            return {'success': False, 'message': 'Failed to register product'}
    
    @staticmethod
    def confirm_blockchain_registration(self, manufacturer_id: str, product_id: str, blockchain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm blockchain registration for a product"""
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(product_id):
                return {'success': False, 'message': 'Invalid ID format'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            product_obj_id = ObjectId(product_id)
            
            # Update product with blockchain confirmation
            result = self.db.products.update_one(
                {
                    '_id': product_obj_id,
                    'manufacturer_id': manufacturer_obj_id,
                    'blockchain_status': 'pending'
                },
                {
                    '$set': {
                        'blockchain_status': 'confirmed',
                        'blockchain_hash': blockchain_data.get('transaction_hash'),
                        'blockchain_block': blockchain_data.get('block_number'),
                        'blockchain_network': blockchain_data.get('network', 'ethereum'),
                        'confirmed_at': datetime.now(timezone.utc),
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count == 0:
                return {'success': False, 'message': 'Product not found or not pending'}
            
            return {
                'success': True,
                'message': 'Blockchain registration confirmed successfully'
            }
            
        except Exception as e:
            logger.error(f"Error confirming blockchain registration: {e}")
            return {'success': False, 'message': 'Failed to confirm blockchain registration'}
    
    @staticmethod
    def mark_blockchain_failed(self, manufacturer_id: str, product_id: str, error_message: str = None) -> Dict[str, Any]:
        """Mark blockchain registration as failed"""
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(product_id):
                return {'success': False, 'message': 'Invalid ID format'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            product_obj_id = ObjectId(product_id)
            
            # Update product with failure status
            result = self.db.products.update_one(
                {
                    '_id': product_obj_id,
                    'manufacturer_id': manufacturer_obj_id,
                    'blockchain_status': 'pending'
                },
                {
                    '$set': {
                        'blockchain_status': 'failed',
                        'blockchain_error': error_message or 'Blockchain registration failed',
                        'failed_at': datetime.now(timezone.utc),
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count == 0:
                return {'success': False, 'message': 'Product not found or not pending'}
            
            return {
                'success': True,
                'message': 'Blockchain registration marked as failed'
            }
            
        except Exception as e:
            logger.error(f"Error marking blockchain failed: {e}")
            return {'success': False, 'message': 'Failed to mark blockchain registration as failed'}
    
    @staticmethod
    def transfer_ownership(self, manufacturer_id: str, transfer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transfer product ownership to another manufacturer"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            product_id = transfer_data.get('product_id')
            new_owner_id = transfer_data.get('new_owner_id')
            
            if not ObjectId.is_valid(product_id) or not ObjectId.is_valid(new_owner_id):
                return {'success': False, 'message': 'Invalid product or new owner ID'}
            
            product_obj_id = ObjectId(product_id)
            new_owner_obj_id = ObjectId(new_owner_id)
            
            # Verify current ownership
            product = self.db.products.find_one({
                '_id': product_obj_id,
                'manufacturer_id': manufacturer_obj_id
            })
            
            if not product:
                return {'success': False, 'message': 'Product not found or not owned by you'}
            
            # Verify new owner exists and is verified manufacturer
            new_owner = self.db.users.find_one({
                '_id': new_owner_obj_id,
                'role': 'manufacturer',
                'verification_status': 'verified'
            })
            
            if not new_owner:
                return {'success': False, 'message': 'New owner not found or not verified'}
            
            # Create ownership transfer record
            transfer_record = {
                'product_id': product_obj_id,
                'from_manufacturer_id': manufacturer_obj_id,
                'to_manufacturer_id': new_owner_obj_id,
                'transfer_reason': transfer_data.get('reason', 'Ownership transfer'),
                'transfer_date': datetime.now(timezone.utc),
                'notes': transfer_data.get('notes', '')
            }
            
            # Insert transfer record
            self.db.ownership_transfers.insert_one(transfer_record)
            
            # Update product ownership
            result = self.db.products.update_one(
                {'_id': product_obj_id},
                {
                    '$set': {
                        'manufacturer_id': new_owner_obj_id,
                        'updated_at': datetime.now(timezone.utc)
                    },
                    '$push': {
                        'ownership_history': {
                            'from_manufacturer_id': manufacturer_obj_id,
                            'to_manufacturer_id': new_owner_obj_id,
                            'transfer_date': datetime.now(timezone.utc),
                            'reason': transfer_data.get('reason', 'Ownership transfer')
                        }
                    }
                }
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'Failed to transfer ownership'}
            
            return {
                'success': True,
                'message': 'Product ownership transferred successfully'
            }
            
        except Exception as e:
            logger.error(f"Error transferring ownership: {e}")
            return {'success': False, 'message': 'Failed to transfer ownership'}
    
    @staticmethod
    def get_product_details(self, product_id: str, manufacturer_id: str = None) -> Dict[str, Any]:
        """Get detailed product information"""
        try:
            if not ObjectId.is_valid(product_id):
                return {'success': False, 'message': 'Invalid product ID'}
            
            product_obj_id = ObjectId(product_id)
            
            # Build query
            query = {'_id': product_obj_id}
            if manufacturer_id and ObjectId.is_valid(manufacturer_id):
                query['manufacturer_id'] = ObjectId(manufacturer_id)
            
            # Get product
            product = self.db.products.find_one(query)
            if not product:
                return {'success': False, 'message': 'Product not found'}
            
            # Get manufacturer info
            manufacturer = self.db.users.find_one(
                {'_id': product['manufacturer_id']},
                {'current_company_name': 1, 'primary_email': 1, 'verification_status': 1}
            )
            
            # Get verification history
            verification_history = list(self.db.verification_logs.find(
                {'serial_number': product['serial_number']},
                {'timestamp': 1, 'result': 1, 'ip_address': 1, 'source': 1}
            ).sort('timestamp', -1).limit(10))
            
            # Convert ObjectIds to strings
            product['_id'] = str(product['_id'])
            product['manufacturer_id'] = str(product['manufacturer_id'])
            
            for verification in verification_history:
                verification['_id'] = str(verification['_id'])
            
            return {
                'success': True,
                'data': {
                    'product': product,
                    'manufacturer': manufacturer,
                    'verification_history': verification_history
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting product details: {e}")
            return {'success': False, 'message': 'Failed to get product details'}
    
    @staticmethod
    def update_product(self, manufacturer_id: str, product_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update product information"""
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(product_id):
                return {'success': False, 'message': 'Invalid ID format'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            product_obj_id = ObjectId(product_id)
            
            # Prepare update fields (only allow certain fields to be updated)
            allowed_fields = ['description', 'specifications', 'batch_number', 'manufacturing_date']
            update_fields = {}
            
            for field in allowed_fields:
                if field in update_data:
                    update_fields[field] = update_data[field]
            
            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}
            
            update_fields['updated_at'] = datetime.now(timezone.utc)
            
            # Update product
            result = self.db.products.update_one(
                {
                    '_id': product_obj_id,
                    'manufacturer_id': manufacturer_obj_id
                },
                {'$set': update_fields}
            )
            
            if result.matched_count == 0:
                return {'success': False, 'message': 'Product not found or not owned by you'}
            
            return {
                'success': True,
                'message': 'Product updated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error updating product: {e}")
            return {'success': False, 'message': 'Failed to update product'}
    
    @staticmethod
    def delete_product(self, manufacturer_id: str, product_id: str) -> Dict[str, Any]:
        """Delete a product (only if not verified on blockchain)"""
        try:
            if not ObjectId.is_valid(manufacturer_id) or not ObjectId.is_valid(product_id):
                return {'success': False, 'message': 'Invalid ID format'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            product_obj_id = ObjectId(product_id)
            
            # Check if product exists and is owned by manufacturer
            product = self.db.products.find_one({
                '_id': product_obj_id,
                'manufacturer_id': manufacturer_obj_id
            })
            
            if not product:
                return {'success': False, 'message': 'Product not found or not owned by you'}
            
            # Don't allow deletion if product is confirmed on blockchain
            if product.get('blockchain_status') == 'confirmed':
                return {'success': False, 'message': 'Cannot delete product that is confirmed on blockchain'}
            
            # Delete the product
            result = self.db.products.delete_one({'_id': product_obj_id})
            
            if result.deleted_count == 0:
                return {'success': False, 'message': 'Failed to delete product'}
            
            return {
                'success': True,
                'message': 'Product deleted successfully'
            }
            
        except Exception as e:
            logger.error(f"Error deleting product: {e}")
            return {'success': False, 'message': 'Failed to delete product'}

    @staticmethod
    def register_product_via_api(self, product_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a product via API"""
        try:
            validation_error = product_validator.validate_product_data(product_data)
            if validation_error:
                return {'success': False, 'error': validation_error}

            existing = self.db.products.find_one({
                'serial_number': product_data['serial_number']
            })
            if existing:
                return {'success': False, 'error': 'Product already exists'}

            manufacturer = self.db.users.find_one({
                '_id': ObjectId(product_data['manufacturer_id'])
            })
            if not manufacturer:
                return {'success': False, 'error': 'Manufacturer not found'}

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
                'created_at': date_helper_utils.date_helper_utils.get_current_utc(),
                'updated_at': date_helper_utils.date_helper_utils.get_current_utc()
            }

            if product_data.get('register_on_blockchain', False):
                try:
                    blockchain_result = self.blockchain_service.register_device(
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
                            'confirmed_at': date_helper_utils.date_helper_utils.get_current_utc()
                        })
                        # Notify via webhook
                        self.webhook_processor.process_blockchain_event({
                            'event_type': 'product_registered',
                            'serial_number': product_data['serial_number'],
                            'transaction_hash': blockchain_result['transaction_hash'],
                            'block_number': blockchain_result.get('block_number'),
                            'manufacturer_address': manufacturer.get('wallet_addresses', [{}])[0].get('address'),
                            'timestamp': date_helper_utils.get_current_utc().isoformat()
                        })
                except Exception as e:
                    logger.warning(f"Blockchain registration failed: {str(e)}")

            result = self.db.products.insert_one(product_doc)
            return {
                'success': True,
                'product_id': str(result.inserted_id),
                'serial_number': product_data['serial_number'],
                'registration_type': product_doc['registration_type'],
                'blockchain_status': product_doc['blockchain_status']
            }

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error registering product: {str(e)}")
            return {'success': False, 'error': 'Failed to register product'}
        except Exception as e:
            logger.error(f"Error registering product: {str(e)}")
            return {'success': False, 'error': 'Failed to register product'}

    @staticmethod
    def get_manufacturer_products_api(self, manufacturer_id: str, page: int = 1, limit: int = 50) -> Dict[str, Any]:
        """Get manufacturer's products for API"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}

            skip = (page - 1) * limit
            products = list(self.db.products.find(
                {'manufacturer_id': ObjectId(manufacturer_id)}
            ).sort('created_at', -1).skip(skip).limit(limit))

            total = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id)
            })

            formatted_products = [format_product_response(p) for p in products]
            return {
                'success': True,
                'products': formatted_products,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'pages': (total + limit - 1) // limit
                }
            }

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error getting products: {str(e)}")
            return {'success': False, 'message': 'Failed to get products'}
        except Exception as e:
            logger.error(f"Error getting products: {str(e)}")
            return {'success': False, 'message': 'Failed to get products'}


product_service = ProductService()