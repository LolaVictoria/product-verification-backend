# services/database_service.py - Fixed version
from models import User, Product, ApiKey
import logging
import os
from pymongo import MongoClient

logger = logging.getLogger(__name__)

class DatabaseService:
    @staticmethod
    def test_connection():
        """Test database connection using direct MongoDB connection"""
        try:
            # Get MongoDB URI from environment
            mongo_uri = os.getenv('MONGO_URI')
            if not mongo_uri:
                logger.error("MONGO_URI not found in environment")
                return False
            
            # Create direct connection for testing
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            
            # Test connection with ping
            client.admin.command('ping')
            
            # Test database access
            db = client.get_default_database()
            
            # Test that we can access collections (without Flask context)
            collections = db.list_collection_names()
            logger.info(f"Database connection test successful. Collections: {collections}")
            
            client.close()
            return True
            
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    @staticmethod
    def test_flask_connection():
        """Test database connection using Flask-PyMongo (requires app context)"""
        try:
            # Try to use User model's collection method
            # This requires Flask-PyMongo to be initialized
            collection = User.get_collection()
            
            # Simple query to test connection
            collection.find_one()  # This doesn't need to find anything, just test connection
            
            logger.info("Flask-PyMongo connection test successful")
            return True
            
        except Exception as e:
            logger.error(f"Flask-PyMongo connection test failed: {e}")
            return False
    
    @staticmethod
    def get_system_stats():
        """Get system statistics"""
        try:
            stats = {
                'total_products': Product.count_verified(),
                'total_manufacturers': User.count_by_role('manufacturer'),
                'total_developers': User.count_by_role('developer'),
                'recent_products_30d': Product.count_recent(30)
            }
            return stats
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}
    
    @staticmethod
    def create_indexes():
        """Create database indexes for performance"""
        try:
            logger.info("Creating database indexes...")
            
            # User indexes
            User.get_collection().create_index("email", unique=True)
            User.get_collection().create_index([("role", 1), ("active", 1)])
            logger.info("✓ User indexes created")
            
            # Product indexes
            Product.collection.create_index("serial_number", unique=True)
            Product.collection.create_index([("manufacturer_id", 1), ("registered_at", -1)])
            Product.collection.create_index("verified")
            logger.info("✓ Product indexes created")
            
            # API Key indexes
            ApiKey.collection.create_index("key", unique=True)
            ApiKey.collection.create_index([("user_id", 1), ("revoked", 1)])
            logger.info("✓ API Key indexes created")
            
            # API Usage indexes
            ApiKey.usage_collection.create_index([("api_key_id", 1), ("timestamp", -1)])
            ApiKey.usage_collection.create_index("timestamp")
            logger.info("✓ API Usage indexes created")
            
            logger.info("Database indexes created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
            return False
    
    @staticmethod
    def cleanup_old_usage_logs(days=90):
        """Clean up old API usage logs"""
        try:
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            result = ApiKey.usage_collection.delete_many({
                'timestamp': {'$lt': cutoff_date}
            })
            logger.info(f"Cleaned up {result.deleted_count} old usage logs")
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to cleanup usage logs: {e}")
            return 0