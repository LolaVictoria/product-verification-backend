# extensions.py 
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from pymongo import MongoClient
import os
import logging

logger = logging.getLogger(__name__)

# Initialize extensions (no app bound yet)
mongo = PyMongo()
jwt = JWTManager()
cors = CORS()

def test_db_connection():
    """Test database connection independently"""
    try:
        # Load environment variable
        connection_string = os.getenv('MONGO_URI')
        
        if not connection_string:
            print("Error: MONGO_URI not found in environment variables")
            return False
        
        print(f"Testing MongoDB connection...")
        print(f"URI: {connection_string[:50]}...")  # Only show first 50 chars for security
        
        # Create client with timeout
        client = MongoClient(connection_string, serverSelectionTimeoutMS=10000)
        
        # Test the connection
        client.admin.command('ping')
        print("Direct MongoDB connection test successful")
        
        # Test database access
        db = client.get_default_database()
        db_name = db.name
        print(f"Connected to database: {db_name}")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"Direct MongoDB connection test failed: {e}")
        logger.error(f"Database connection test failed: {e}")
        return False

def init_database(app):
    """Initialize database connection with Flask app"""
    try:
        # Check if MONGO_URI is in Flask config
        mongo_uri = app.config.get('MONGO_URI')
        if not mongo_uri:
            print("Error: MONGO_URI not found in Flask app config")
            print("Available config keys:", list(app.config.keys()))
            return False
        
        print(f"Initializing Flask-PyMongo with URI: {mongo_uri[:50]}...")
        
        # Initialize PyMongo with Flask app
        mongo.init_app(app)
        
        # Test the connection within app context
        with app.app_context():
            try:
                # Test if we can ping the database
                result = mongo.db.command('ping')
                print("Database connected successfully")
                print(f"Database name: {mongo.db.name}")
                
                # Create indexes after successful connection
                create_all_indexes()
                print("Database initialization completed successfully")
                return True
                
            except Exception as e:
                print(f"Database ping failed: {e}")
                logger.error(f"Database ping failed: {e}")
                return False
        
    except Exception as e:
        print(f"Database initialization failed: {e}")
        logger.error(f"Database initialization failed: {e}")
        return False

def create_all_indexes():
    """Create all database indexes"""
    try:
        print("Creating database indexes...")
        
        # Try to use your DatabaseService if it exists
        try:
            from services.database_service import DatabaseService
            if DatabaseService.create_indexes():
                print("Indexes created using DatabaseService")
                return True
        except ImportError:
            print("DatabaseService not found, creating indexes manually")
        
        # Fallback: Create indexes manually
        create_manual_indexes()
        print("All database indexes created successfully")
        return True
        
    except Exception as e:
        print(f"Failed to create indexes: {e}")
        logger.error(f"Failed to create indexes: {e}")
        return False

def create_manual_indexes():
    """Create indexes manually if models don't have create_indexes methods"""
    try:
        # Product indexes
        products_collection = mongo.db.products
        products_collection.create_index("serial_number", unique=True)
        products_collection.create_index("manufacturer_id")
        products_collection.create_index("registered_at")
        products_collection.create_index("verified")
        products_collection.create_index([("manufacturer_id", 1), ("registered_at", -1)])
        print("✓ Product indexes created")
        
        # User indexes
        users_collection = mongo.db.users
        users_collection.create_index("email", unique=True)
        users_collection.create_index("wallet_address", unique=True, sparse=True)
        users_collection.create_index([("role", 1), ("active", 1)])
        print("✓ User indexes created")
        
        # API Key indexes
        api_keys_collection = mongo.db.api_keys
        api_keys_collection.create_index("key", unique=True)
        api_keys_collection.create_index([("user_id", 1), ("revoked", 1)])
        print("✓ API Key indexes created")
        
        # API Usage indexes
        api_usage_collection = mongo.db.api_usage
        api_usage_collection.create_index([("api_key_id", 1), ("timestamp", -1)])
        api_usage_collection.create_index("timestamp")
        print("✓ API Usage indexes created")
        
    except Exception as e:
        print(f"Manual index creation failed: {e}")
        raise

def get_db():
    """Get database instance for use in routes"""
    return mongo.db

def get_mongo_client():
    """Get MongoDB client for advanced operations"""
    return mongo.cx

def check_database_health():
    """Check database health and return status"""
    try:
        # Test basic connectivity
        mongo.db.command('ping')
        
        # Get server status
        status = mongo.db.command('serverStatus')
        
        # Get database stats
        stats = mongo.db.command('dbStats')
        
        return {
            'connected': True,
            'database_name': mongo.db.name,
            'collections': mongo.db.list_collection_names(),
            'database_size': stats.get('dataSize', 0),
            'uptime': status.get('uptime', 0)
        }
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            'connected': False,
            'error': str(e)
        }