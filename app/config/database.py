"""
Database Configuration and Connection Management
Centralized database connection with singleton pattern
"""

import os
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from typing import Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Global connection instances
_db_connection = None
_mongo_client = None


def get_db_connection():
    """
    Get database connection with connection pooling (singleton pattern)
    Returns the same connection instance across the application
    
    Returns:
        Database: MongoDB database instance
    """
    global _db_connection, _mongo_client
    
    if _db_connection is None:
        try:
            connection_string = os.getenv('MONGODB_URI')
            if not connection_string:
                raise ValueError("MONGODB_URI environment variable not set")
            
            # Create MongoDB client with connection pooling
            _mongo_client = MongoClient(
                connection_string,
                maxPoolSize=50,
                minPoolSize=10,
                maxIdleTimeMS=30000,
                serverSelectionTimeoutMS=30000
            )
            
            # Test connection
            _mongo_client.admin.command('ping')
            
            # Get database name from environment
            db_name = os.getenv('DATABASE_NAME', 'product_verification')
            _db_connection = _mongo_client[db_name]
            
            logger.info(f"Connected to database: {db_name}")
            
        except ConnectionFailure as e:
            logger.error(f"Database connection failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            raise
    
    return _db_connection


def close_db_connection():
    """
    Close database connection and cleanup resources
    Should be called on application shutdown
    """
    global _db_connection, _mongo_client
    
    if _mongo_client:
        try:
            _mongo_client.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
        finally:
            _db_connection = None
            _mongo_client = None


def get_client() -> Optional[MongoClient]:
    """
    Get the raw MongoDB client instance
    Useful for admin operations or transactions
    
    Returns:
        MongoClient: MongoDB client instance or None
    """
    global _mongo_client
    return _mongo_client


def reset_connection():
    """
    Force reset the database connection
    Useful for testing or reconnection scenarios
    """
    global _db_connection, _mongo_client
    
    if _mongo_client:
        try:
            _mongo_client.close()
        except:
            pass
    
    _db_connection = None
    _mongo_client = None
    
    # Reconnect
    return get_db_connection()