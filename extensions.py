# extensions.py
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from pymongo import MongoClient
import os

# Initialize extensions (no app bound yet)
mongo = PyMongo()
jwt = JWTManager()
cors = CORS()
# extensions.py
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from pymongo import MongoClient
import os

# Initialize extensions (no app bound yet)
mongo = PyMongo()
jwt = JWTManager()
cors = CORS()

def init_database(app):
    """Initialize database connection"""
    try:
        # Initialize PyMongo with Flask app
        mongo.init_app(app)
        
        # Test the connection
        with app.app_context():
            # Test if we can ping the database
            mongo.db.command('ping')
            print("Database connected successfully")
            
            # Create indexes after successful connection
            create_all_indexes()
            
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False

def create_all_indexes():
    """Create all database indexes"""
    try:
        # Import here to avoid circular imports
        from models.product import Product
        # from models.user import User  # Uncomment if you have a User model
        
        # Create product indexes
        Product.create_indexes()
        
        # Create user indexes if needed
        # User.create_indexes()
        
        print("All database indexes created successfully")
    except Exception as e:
        print(f"Failed to create indexes: {e}")

def test_db_connection():
    """Test database connection independently"""
    try:
        connection_string = os.getenv('MONGO_URI', 'mongodb://localhost:27017/product_verification')
        client = MongoClient(connection_string)
        
        # Test the connection
        client.admin.command('ping')
        print("Direct MongoDB connection test successful")
        
        client.close()
        return True
    except Exception as e:
        print(f"Direct MongoDB connection test failed: {e}")
        return False
def init_database(app):
    """Initialize database connection"""
    try:
        # Initialize PyMongo with Flask app
        mongo.init_app(app)
        
        # Test the connection
        with app.app_context():
            # Test if we can ping the database
            mongo.db.command('ping')
            print("Database connected successfully")
            
            # Create indexes after successful connection
            create_all_indexes()
            
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False

def create_all_indexes():
    """Create all database indexes"""
    try:
        # Import here to avoid circular imports
        from models.product import Product
        # from models.user import User  # Uncomment if you have a User model
        
        # Check if Product has create_indexes method
        if hasattr(Product, 'create_indexes'):
            Product.create_indexes()
        else:
            print("Warning: Product model doesn't have create_indexes method")
            # Fallback: create indexes manually
            collection = Product.get_collection()
            collection.create_index("serial_number", unique=True)
            collection.create_index("manufacturer_id")
            collection.create_index("registered_at")
            print("Product indexes created manually")
        
        print("All database indexes created successfully")
    except Exception as e:
        print(f"Failed to create indexes: {e}")

def test_db_connection():
    """Test database connection independently"""
    try:
        connection_string = os.getenv('MONGO_URI', 'mongodb://localhost:27017/product_verification')
        client = MongoClient(connection_string)
        
        # Test the connection
        client.admin.command('ping')
        print("Direct MongoDB connection test successful")
        
        client.close()
        return True
    except Exception as e:
        print(f"Direct MongoDB connection test failed: {e}")
        return False