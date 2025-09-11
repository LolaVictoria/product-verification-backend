from datetime import datetime
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
import logging
import os
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class ProductService:
    """Service class for handling product-related database operations"""
    
    def __init__(self, db_connection=None):
        """Initialize the ProductService with database connection"""
        if db_connection:
            self.db = db_connection
        else:
            # Initialize MongoDB connection
            mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
            db_name = os.getenv('DATABASE_NAME', 'product_registry')
            
            try:
                self.client = MongoClient(mongo_uri)
                self.db = self.client[db_name]
                self.products = self.db.products
                
                # Create indexes for better performance
                self._create_indexes()
                
                logger.info("ProductService initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize ProductService: {e}")
                raise
    
    def _create_indexes(self):
        """Create necessary indexes for the products collection"""
        try:
            # Create unique index on serial_number
            self.products.create_index("serial_number", unique=True)
            
            # Create indexes for common queries
            self.products.create_index("manufacturer_id")
            self.products.create_index("brand")
            self.products.create_index("device_type")
            self.products.create_index("created_at")
            
            # Create text index for search functionality
            self.products.create_index([
                ("serial_number", "text"),
                ("brand", "text"),
                ("model", "text"),
                ("device_type", "text")
            ])
            
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.warning(f"Error creating indexes: {e}")
    
    def register_product(self, product_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new product in the database"""
        try:
            # Check if product with serial number already exists
            existing_product = self.products.find_one({
                'serial_number': product_data['serial_number']
            })
            
            if existing_product:
                return {
                    'success': False,
                    'error': 'Product with this serial number already exists',
                    'error_code': 'DUPLICATE_SERIAL'
                }
            
            # Insert the product
            result = self.products.insert_one(product_data)
            
            if result.inserted_id:
                # Retrieve the inserted product
                product = self.products.find_one({'_id': result.inserted_id})
                
                logger.info(f"Product registered successfully: {product_data['serial_number']}")
                return {
                    'success': True,
                    'product': product,
                    'product_id': str(result.inserted_id)
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to register product'
                }
                
        except DuplicateKeyError:
            return {
                'success': False,
                'error': 'Product with this serial number already exists',
                'error_code': 'DUPLICATE_SERIAL'
            }
        except Exception as e:
            logger.error(f"Error registering product: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while registering product'
            }
    
    def get_product_by_id(self, product_id: ObjectId) -> Dict[str, Any]:
        """Get a product by its ID"""
        try:
            product = self.products.find_one({'_id': product_id})
            
            if product:
                return {
                    'success': True,
                    'product': product
                }
            else:
                return {
                    'success': False,
                    'error': 'Product not found'
                }
                
        except Exception as e:
            logger.error(f"Error getting product by ID: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while fetching product'
            }
    
    def get_product_by_serial(self, serial_number: str) -> Dict[str, Any]:
        """Get a product by its serial number"""
        try:
            product = self.products.find_one({'serial_number': serial_number})
            
            if product:
                return {
                    'success': True,
                    'product': product
                }
            else:
                return {
                    'success': False,
                    'error': 'Product not found'
                }
                
        except Exception as e:
            logger.error(f"Error getting product by serial: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while fetching product'
            }
    
    def get_products_by_manufacturer(self, manufacturer_id: ObjectId, page: int = 1, limit: int = 10) -> Dict[str, Any]:
        """Get all products for a specific manufacturer with pagination"""
        try:
            skip = (page - 1) * limit
            
            # Get products with pagination
            products = list(self.products.find(
                {'manufacturer_id': manufacturer_id}
            ).sort('created_at', -1).skip(skip).limit(limit))
            
            # Get total count
            total = self.products.count_documents({'manufacturer_id': manufacturer_id})
            
            return {
                'success': True,
                'products': products,
                'total': total,
                'page': page,
                'limit': limit,
                'has_more': (skip + limit) < total
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer products: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while fetching products'
            }
    
    def update_product(self, product_id: ObjectId, update_data: Dict[str, Any], manufacturer_id: ObjectId) -> Dict[str, Any]:
        """Update a product (only by its manufacturer)"""
        try:
            # First check if product exists and belongs to manufacturer
            existing_product = self.products.find_one({
                '_id': product_id,
                'manufacturer_id': manufacturer_id
            })
            
            if not existing_product:
                return {
                    'success': False,
                    'error': 'Product not found or you do not have permission to update it'
                }
            
            # Remove fields that shouldn't be updated directly
            restricted_fields = ['_id', 'manufacturer_id', 'created_at', 'registered_at', 'ownership_history']
            for field in restricted_fields:
                update_data.pop(field, None)
            
            # Update the product
            result = self.products.update_one(
                {'_id': product_id, 'manufacturer_id': manufacturer_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                # Return updated product
                updated_product = self.products.find_one({'_id': product_id})
                logger.info(f"Product updated successfully: {product_id}")
                return {
                    'success': True,
                    'product': updated_product
                }
            else:
                return {
                    'success': False,
                    'error': 'No changes were made to the product'
                }
                
        except Exception as e:
            logger.error(f"Error updating product: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while updating product'
            }
    
    def verify_product(self, product_id: ObjectId) -> Dict[str, Any]:
        """Verify product authenticity"""
        try:
            product = self.products.find_one({'_id': product_id})
            
            if not product:
                return {
                    'success': False,
                    'error': 'Product not found'
                }
            
            # Create verification data
            verification_data = {
                'product_id': str(product_id),
                'serial_number': product['serial_number'],
                'verified': True,
                'verification_method': 'database',
                'verified_at': datetime.utcnow().isoformat(),
                'status': 'authentic',
                'manufacturer': {
                    'id': str(product['manufacturer_id']),
                    'name': product.get('manufacturer_name', '')
                },
                'product_details': {
                    'brand': product['brand'],
                    'model': product['model'],
                    'device_type': product['device_type'],
                    'registered_at': product['registered_at'].isoformat() if product.get('registered_at') else None
                },
                'blockchain_verified': product.get('blockchain_verified', False)
            }
            
            # Update verification timestamp
            self.products.update_one(
                {'_id': product_id},
                {'$set': {'last_verified_at': datetime.utcnow()}}
            )
            
            return {
                'success': True,
                'verification': verification_data
            }
            
        except Exception as e:
            logger.error(f"Error verifying product: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while verifying product'
            }
    
    def search_products(self, search_params: Dict[str, Any]) -> Dict[str, Any]:
        """Search products based on various criteria"""
        try:
            query = search_params.get('query', '').strip()
            brand = search_params.get('brand', '').strip()
            device_type = search_params.get('device_type', '').strip()
            page = search_params.get('page', 1)
            limit = search_params.get('limit', 10)
            
            skip = (page - 1) * limit
            
            # Build search filter
            search_filter = {}
            
            # Text search across multiple fields
            if query:
                search_filter['$text'] = {'$search': query}
            
            # Specific field filters
            if brand:
                search_filter['brand'] = {'$regex': brand, '$options': 'i'}
            
            if device_type:
                search_filter['device_type'] = {'$regex': device_type, '$options': 'i'}
            
            # Execute search with pagination
            if query and not brand and not device_type:
                # Use text search scoring when only using text query
                products = list(self.products.find(
                    search_filter,
                    {'score': {'$meta': 'textScore'}}
                ).sort([('score', {'$meta': 'textScore'})]).skip(skip).limit(limit))
            else:
                products = list(self.products.find(search_filter)
                              .sort('created_at', -1)
                              .skip(skip)
                              .limit(limit))
            
            # Get total count
            total = self.products.count_documents(search_filter)
            
            return {
                'success': True,
                'products': products,
                'total': total,
                'page': page,
                'limit': limit,
                'has_more': (skip + limit) < total,
                'search_params': search_params
            }
            
        except Exception as e:
            logger.error(f"Error searching products: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while searching products'
            }
    
    def delete_product(self, product_id: ObjectId, manufacturer_id: ObjectId) -> Dict[str, Any]:
        """Delete a product (only by its manufacturer)"""
        try:
            result = self.products.delete_one({
                '_id': product_id,
                'manufacturer_id': manufacturer_id
            })
            
            if result.deleted_count > 0:
                logger.info(f"Product deleted successfully: {product_id}")
                return {
                    'success': True,
                    'message': 'Product deleted successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Product not found or you do not have permission to delete it'
                }
                
        except Exception as e:
            logger.error(f"Error deleting product: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while deleting product'
            }
    
    def get_product_stats(self, manufacturer_id: Optional[ObjectId] = None) -> Dict[str, Any]:
        """Get product statistics"""
        try:
            pipeline = []
            
            # Filter by manufacturer if provided
            if manufacturer_id:
                pipeline.append({'$match': {'manufacturer_id': manufacturer_id}})
            
            # Aggregation pipeline for statistics
            pipeline.extend([
                {
                    '$group': {
                        '_id': None,
                        'total_products': {'$sum': 1},
                        'brands': {'$addToSet': '$brand'},
                        'device_types': {'$addToSet': '$device_type'},
                        'verified_products': {
                            '$sum': {'$cond': [{'$eq': ['$blockchain_verified', True]}, 1, 0]}
                        }
                    }
                },
                {
                    '$project': {
                        '_id': 0,
                        'total_products': 1,
                        'total_brands': {'$size': '$brands'},
                        'total_device_types': {'$size': '$device_types'},
                        'verified_products': 1,
                        'verification_rate': {
                            '$multiply': [
                                {'$divide': ['$verified_products', '$total_products']},
                                100
                            ]
                        }
                    }
                }
            ])
            
            result = list(self.products.aggregate(pipeline))
            
            if result:
                stats = result[0]
            else:
                stats = {
                    'total_products': 0,
                    'total_brands': 0,
                    'total_device_types': 0,
                    'verified_products': 0,
                    'verification_rate': 0
                }
            
            return {
                'success': True,
                'stats': stats
            }
            
        except Exception as e:
            logger.error(f"Error getting product stats: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while getting statistics'
            }
    
    def update_ownership_history(self, product_id: ObjectId, ownership_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update product ownership history"""
        try:
            # Add timestamp to ownership data
            ownership_data['timestamp'] = datetime.utcnow().isoformat()
            
            result = self.products.update_one(
                {'_id': product_id},
                {
                    '$push': {'ownership_history': ownership_data},
                    '$set': {'updated_at': datetime.utcnow()}
                }
            )
            
            if result.modified_count > 0:
                return {
                    'success': True,
                    'message': 'Ownership history updated successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Product not found'
                }
                
        except Exception as e:
            logger.error(f"Error updating ownership history: {e}")
            return {
                'success': False,
                'error': 'Database error occurred while updating ownership history'
            }

# Create a singleton instance
try:
    product_service = ProductService()
except Exception as e:
    logger.error(f"Failed to create ProductService instance: {e}")
    product_service = None

product_service = ProductService