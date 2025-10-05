# tests/conftest.py
import pytest
from app import create_app
from app.config.database import get_db_connection
import os

@pytest.fixture
def app():
    """Create test app"""
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['MONGODB_URI'] = 'mongodb://localhost:27017/test_db'
    
    app = create_app()
    app.config['TESTING'] = True
    
    with app.app_context():
        yield app
        
        # Cleanup test database
        db = get_db_connection()
        db.drop_collection('users')
        db.drop_collection('products')

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def auth_headers():
    """Create authorization headers for testing"""
    # Create test user and get JWT token
    return {'Authorization': 'Bearer test-jwt-token'}