# migrations/001_initial_schema.py
"""
Initial database schema migration
Creates collections and basic indexes
"""
from pymongo import MongoClient
import os
from datetime import datetime

def up():
    """Apply migration"""
    client = MongoClient(os.getenv('MONGODB_URI'))
    db = client.get_default_database()
    
    # Create collections with validators
    collections = [
        'users',
        'manufacturers', 
        'products',
        'verifications',
        'api_keys',
        'counterfeit_reports',
        'ownership_transfers',
        'billing',
        'webhook_logs'
    ]
    
    for collection in collections:
        if collection not in db.list_collection_names():
            db.create_collection(collection)
            print(f"Created collection: {collection}")
    
    # Basic indexes
    indexes = [
        ('users', [('primary_email', 1)], {'unique': True, 'sparse': True}),
        ('users', [('role', 1)], {}),
        ('products', [('serial_number', 1)], {'unique': True}),
        ('products', [('manufacturer_id', 1)], {}),
        ('verifications', [('serial_number', 1)], {}),
        ('verifications', [('timestamp', -1)], {}),
        ('api_keys', [('key_hash', 1)], {'unique': True}),
        ('api_keys', [('manufacturer_id', 1)], {}),
    ]
    
    for collection, index_spec, options in indexes:
        try:
            db[collection].create_index(index_spec, **options)
            print(f"Created index on {collection}: {index_spec}")
        except Exception as e:
            print(f"Index already exists or error: {e}")
    
    # Record migration
    db.migrations.insert_one({
        'version': '001',
        'name': 'initial_schema',
        'applied_at': datetime.utcnow()
    })
    
    print("Migration 001_initial_schema completed")

def down():
    """Reverse migration (optional)"""
    print("Migration 001 cannot be reversed - it's the initial schema")

if __name__ == '__main__':
    up()