
from flask_pymongo import PyMongo

mongo = PyMongo()

def init_db(app):
    """Initialize database connection"""
    mongo.init_app(app)
    return mongo

def get_db():
    """Get database instance"""
    return mongo.db