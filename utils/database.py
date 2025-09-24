import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Global database connection
_db_connection = None

def get_db_connection():
    """Get database connection with connection pooling"""
    global _db_connection
    
    if _db_connection is None:
        try:
            connection_string = os.getenv('MONGODB_URI')
            if not connection_string:
                raise ValueError("MONGODB_URI environment variable not set")
            
            client = MongoClient(
                connection_string,
                maxPoolSize=50,
                minPoolSize=10,
                maxIdleTimeMS=30000,
                serverSelectionTimeoutMS=30000
            )
            
            # Test connection
            client.admin.command('ping')
            
            db_name = os.getenv('DATABASE_NAME')
            _db_connection = client[db_name]
            
            logger.info(f"Connected to database: {db_name}")
            
        except ConnectionFailure as e:
            logger.error(f"Database connection failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            raise
    
    return _db_connection

def close_db_connection():
    """Close database connection"""
    global _db_connection
    if _db_connection:
        _db_connection.client.close()
        _db_connection = None

def init_database_indexes():
    """Initialize database indexes for performance"""
    try:
        db = get_db_connection()
        
        # Drop existing conflicting indexes first
        conflicting_indexes = [
            ("users", "primary_email_1"),
            ("products", "serial_number_1"),
            ("products", "manufacturer_id_1"),
            ("products", "registration_type_1"),
            ("products", "created_at_1"),
            ("products", "brand_1_model_1"),
            ("verifications", "serial_number_1"),
            ("api_keys", "key_hash_1"),
            ("ownership_transfers", "serial_number_1"),
        ]
        
        for collection_name, index_name in conflicting_indexes:
            try:
                db[collection_name].drop_index(index_name)
            except:
                pass  # Index doesn't exist, continue
        
        # Users collection indexes
        db.users.create_index("primary_email", unique=True, sparse=True)
        db.users.create_index("role")
        db.users.create_index("verification_status")
        db.users.create_index("created_at")
        
        # Products collection indexes
        db.products.create_index("serial_number", unique=True)
        db.products.create_index("manufacturer_id")
        db.products.create_index("registration_type")
        db.products.create_index("created_at")
        db.products.create_index([("brand", 1), ("model", 1)])
        db.products.create_index("public_key", unique=True, sparse=True) 
        
        # Verifications collection indexes
        db.verifications.create_index("serial_number")
        db.verifications.create_index("timestamp")
        db.verifications.create_index("result")
        db.verifications.create_index("ip_address")
        db.verifications.create_index([("serial_number", 1), ("timestamp", -1)])  # Composite for queries
        
        
        # API keys collection indexes
        db.api_keys.create_index("key_hash", unique=True)
        db.api_keys.create_index("manufacturer_id")
        db.api_keys.create_index("status")
        db.api_keys.create_index("created_at")
        
        # Ownership transfers collection indexes
        db.ownership_transfers.create_index("serial_number")
        db.ownership_transfers.create_index("from_manufacturer_id")
        db.ownership_transfers.create_index("transfer_date")
        
        # Rate limiting collection indexes
        db.rate_limit_logs.create_index([("identifier", 1), ("timestamp", -1)])
        db.rate_limit_logs.create_index("timestamp", expireAfterSeconds=86400)
        
        # Security logs collection indexes
        db.security_logs.create_index("user_id")
        db.security_logs.create_index("event_type")
        db.security_logs.create_index("timestamp")
        db.security_logs.create_index("ip_address")
        
        # Notification logs collection indexes
        db.notification_logs.create_index("type")
        db.notification_logs.create_index("timestamp")
        db.notification_logs.create_index("recipient")
        
        logger.info("Database indexes initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing database indexes: {e}")

def check_database_health():
    """Check database connection health"""
    try:
        db = get_db_connection()
        # Run a simple ping command
        db.command('ping')
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

def get_collection_stats():
    """Get database collection statistics"""
    try:
        db = get_db_connection()
        stats = {}
        
        collections = ['users', 'products', 'verifications', 'api_keys', 
                      'ownership_transfers', 'rate_limit_logs', 'security_logs']
        
        for collection_name in collections:
            collection = db[collection_name]
            stats[collection_name] = {
                'count': collection.count_documents({}),
                'size': collection.estimated_document_count()
            }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting collection stats: {e}")
        return {}