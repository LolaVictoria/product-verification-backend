"""
Database Helper Utilities
Pure helper functions for database operations, index management, and health checks
Does not manage connections - only provides utilities for working with databases
"""

import logging
from typing import Dict, List, Tuple
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def init_database_indexes():
    """
    Initialize database indexes for performance optimization
    Should be called once during application startup
    
    Raises:
        Exception: If index creation fails
    """
    from app.config.database import get_db_connection
    
    try:
        db = get_db_connection()
        
        # Define conflicting indexes to drop (for clean setup)
        conflicting_indexes: List[Tuple[str, str]] = [
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
        
        # Drop existing conflicting indexes
        for collection_name, index_name in conflicting_indexes:
            try:
                db[collection_name].drop_index(index_name)
                logger.debug(f"Dropped index {index_name} from {collection_name}")
            except Exception:
                pass  # Index doesn't exist - continue
        
        # Users collection indexes
        logger.info("Creating indexes for 'users' collection...")
        db.users.create_index("primary_email", unique=True, sparse=True)
        db.users.create_index("role")
        db.users.create_index("verification_status")
        db.users.create_index("created_at")
        
        # Products collection indexes
        logger.info("Creating indexes for 'products' collection...")
        db.products.create_index("serial_number", unique=True)
        db.products.create_index("manufacturer_id")
        db.products.create_index("registration_type")
        db.products.create_index("created_at")
        db.products.create_index([("brand", 1), ("model", 1)])
        db.products.create_index("public_key", unique=True, sparse=True)
        
        # Verifications collection indexes
        logger.info("Creating indexes for 'verifications' collection...")
        db.verifications.create_index("serial_number")
        db.verifications.create_index("timestamp")
        db.verifications.create_index("result")
        db.verifications.create_index("ip_address")
        db.verifications.create_index([("serial_number", 1), ("timestamp", -1)])
        
        # API keys collection indexes
        logger.info("Creating indexes for 'api_keys' collection...")
        db.api_keys.create_index("key_hash", unique=True)
        db.api_keys.create_index("manufacturer_id")
        db.api_keys.create_index("status")
        db.api_keys.create_index("created_at")
        
        # Ownership transfers collection indexes
        logger.info("Creating indexes for 'ownership_transfers' collection...")
        db.ownership_transfers.create_index("serial_number")
        db.ownership_transfers.create_index("from_manufacturer_id")
        db.ownership_transfers.create_index("transfer_date")
        
        # Rate limiting collection indexes
        logger.info("Creating indexes for 'rate_limit_logs' collection...")
        db.rate_limit_logs.create_index([("identifier", 1), ("timestamp", -1)])
        db.rate_limit_logs.create_index("timestamp", expireAfterSeconds=86400)
        
        # Security logs collection indexes
        logger.info("Creating indexes for 'security_logs' collection...")
        db.security_logs.create_index("user_id")
        db.security_logs.create_index("event_type")
        db.security_logs.create_index("timestamp")
        db.security_logs.create_index("ip_address")
        
        # Notification logs collection indexes
        logger.info("Creating indexes for 'notification_logs' collection...")
        db.notification_logs.create_index("type")
        db.notification_logs.create_index("timestamp")
        db.notification_logs.create_index("recipient")
        
        logger.info("✓ Database indexes initialized successfully")
        
    except Exception as e:
        logger.error(f"✗ Error initializing database indexes: {e}")
        raise


def check_database_health() -> bool:
    """
    Check database connection health with ping command
    
    Returns:
        bool: True if database is healthy, False otherwise
    """
    from app.config.database import get_db_connection
    
    try:
        db = get_db_connection()
        db.command('ping')
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def get_collection_stats() -> Dict[str, Dict[str, int]]:
    """
    Get statistics for all main collections
    Useful for monitoring and admin dashboards
    
    Returns:
        Dict: Collection statistics with count and size
    """
    from app.config.database import get_db_connection
    
    try:
        db = get_db_connection()
        stats = {}
        
        collections = [
            'users', 
            'products', 
            'verifications', 
            'api_keys',
            'ownership_transfers', 
            'rate_limit_logs', 
            'security_logs',
            'manufacturers',
            'customers',
            'billing',
            'webhook_logs'
        ]
        
        for collection_name in collections:
            try:
                collection = db[collection_name]
                stats[collection_name] = {
                    'count': collection.count_documents({}),
                    'size': collection.estimated_document_count()
                }
            except Exception as e:
                logger.warning(f"Could not get stats for {collection_name}: {e}")
                stats[collection_name] = {'count': 0, 'size': 0}
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting collection stats: {e}")
        return {}


def verify_indexes_exist() -> Dict[str, List[str]]:
    """
    Verify that all expected indexes exist
    Returns a report of missing indexes per collection
    
    Returns:
        Dict: Missing indexes by collection
    """
    from app.config.database import get_db_connection
    
    try:
        db = get_db_connection()
        
        expected_indexes = {
            'users': ['primary_email_1', 'role_1', 'verification_status_1', 'created_at_1'],
            'products': ['serial_number_1', 'manufacturer_id_1', 'registration_type_1'],
            'verifications': ['serial_number_1', 'timestamp_1', 'result_1'],
            'api_keys': ['key_hash_1', 'manufacturer_id_1', 'status_1'],
        }
        
        missing_indexes = {}
        
        for collection_name, expected in expected_indexes.items():
            collection = db[collection_name]
            existing = [idx['name'] for idx in collection.list_indexes()]
            
            missing = [idx for idx in expected if idx not in existing]
            if missing:
                missing_indexes[collection_name] = missing
        
        return missing_indexes
        
    except Exception as e:
        logger.error(f"Error verifying indexes: {e}")
        return {}


def get_database_info() -> Dict:
    """
    Get general database information
    Useful for debugging and monitoring
    
    Returns:
        Dict: Database metadata
    """
    from app.config.database import get_db_connection, get_client
    
    try:
        db = get_db_connection()
        client = get_client()
        
        if not client:
            return {'error': 'No database client available'}
        
        server_info = client.server_info()
        
        return {
            'database_name': db.name,
            'mongodb_version': server_info.get('version', 'unknown'),
            'collections': db.list_collection_names(),
            'collection_count': len(db.list_collection_names()),
            'connection_status': 'connected'
        }
        
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
        return {'error': str(e), 'connection_status': 'error'}


def cleanup_expired_data():
    """
    Cleanup expired or old data from collections
    Should be run periodically (e.g., via cron job)
    """
    from app.config.database import get_db_connection
    
    try:
        db = get_db_connection()
        
        # Cleanup old rate limit logs (older than 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        result = db.rate_limit_logs.delete_many({
            'timestamp': {'$lt': seven_days_ago}
        })
        
        logger.info(f"Cleaned up {result.deleted_count} old rate limit logs")
        
    except Exception as e:
        logger.error(f"Error during data cleanup: {e}")