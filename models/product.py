from datetime import datetime, timedelta
from extensions import mongo
from bson import ObjectId

class Product:
    @staticmethod
    def get_collection():
        return mongo.db.products  # Fixed: Changed from 'users' to 'products'
    
    @staticmethod
    def create_indexes():
        """Create database indexes for better performance"""
        collection = Product.get_collection()
        try:
            # Create index on serial_number for uniqueness and fast lookups
            collection.create_index("serial_number", unique=True)
            # Create index on manufacturer_id for fast manufacturer queries
            collection.create_index("manufacturer_id")
            # Create index on registered_at for sorting
            collection.create_index("registered_at")
            print("Product indexes created successfully")
        except Exception as e:
            print(f"Error creating product indexes: {e}")
    
    @staticmethod
    def create_product(serial_number, product_name, category, description,
                      manufacturer_id, manufacturer_address, tx_hash):
        """Create a new product"""
        product_data = {
            'serial_number': serial_number,
            'product_name': product_name,
            'category': category,
            'description': description,
            'manufacturer_id': ObjectId(manufacturer_id),
            'manufacturer_address': manufacturer_address,
            'blockchain_tx_hash': tx_hash,
            'registered_at': datetime.utcnow(),
            'verified': True
        }
        return Product.get_collection().insert_one(product_data)
    
    @staticmethod
    def find_by_serial_number(serial_number):
        """Find product by serial number"""
        return Product.get_collection().find_one({'serial_number': serial_number})
    
    @staticmethod
    def find_by_manufacturer(manufacturer_id, page=1, per_page=10):
        """Find products by manufacturer with pagination"""
        skip = (page - 1) * per_page
        products = list(Product.get_collection().find(
            {'manufacturer_id': ObjectId(manufacturer_id)}
        ).sort('registered_at', -1).skip(skip).limit(per_page))
        total = Product.get_collection().count_documents({'manufacturer_id': ObjectId(manufacturer_id)})
        return products, total
    
    @staticmethod
    def serial_exists(serial_number):
        """Check if serial number already exists"""
        return Product.get_collection().find_one({'serial_number': serial_number}) is not None
    
    @staticmethod
    def count_verified():
        """Count verified products"""
        return Product.get_collection().count_documents({'verified': True})
    
    @staticmethod
    def count_recent(days=30):
        """Count products registered in the last N days"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        return Product.get_collection().count_documents({
            'registered_at': {'$gte': cutoff_date}
        })