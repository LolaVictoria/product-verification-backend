# migrations/002_add_indexes.py
"""
Add performance indexes migration
"""
from pymongo import MongoClient
import os
from datetime import datetime

def up():
    """Apply migration"""
    client = MongoClient(os.getenv('MONGODB_URI'))
    db = client.get_default_database()
    
    # Performance indexes
    performance_indexes = [
        ('products', [('brand', 1), ('model', 1)], {}),
        ('products', [('created_at', -1)], {}),
        ('products', [('blockchain_verified', 1)], {}),
        ('verifications', [('manufacturer_id', 1), ('timestamp', -1)], {}),
        ('verifications', [('is_authentic', 1)], {}),
        ('api_keys', [('last_used', -1)], {}),
        ('users', [('created_at', -1)], {})
    ]
    up()