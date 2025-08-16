from models import User, Product, ApiKey
import logging

logger = logging.getLogger(__name__)

class DatabaseService:
    @staticmethod
    def test_connection():
        """Test database connection"""
        try:
            User.get_collection().find_one()
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
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
            # User indexes
            User.get_collection().create_index("email", unique=True)
            User.get_collection().create_index([("role", 1), ("active", 1)])
            
            # Product indexes
            Product.collection.create_index("serial_number", unique=True)
            Product.collection.create_index([("manufacturer_id", 1), ("registered_at", -1)])
            Product.collection.create_index("verified")
            
            # API Key indexes
            ApiKey.collection.create_index("key", unique=True)
            ApiKey.collection.create_index([("user_id", 1), ("revoked", 1)])
            
            # API Usage indexes
            ApiKey.usage_collection.create_index([("api_key_id", 1), ("timestamp", -1)])
            ApiKey.usage_collection.create_index("timestamp")
            
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