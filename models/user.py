from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import mongo
from bson import ObjectId

class User:
    @staticmethod
    def get_collection():
        """Return the users collection"""
        return mongo.db.users
    
    @staticmethod
    def create_user(username, email, password, role, wallet_address=None):
        """Create a new user"""
        user_data = {
            'username': username.lower(),  # Fixed: Added missing comma
            'email': email.lower().strip(),
            'password_hash': generate_password_hash(password),
            'role': role.lower(),
            'wallet_address': wallet_address or '',
            'created_at': datetime.utcnow(),
            'active': True
        }
        return User.get_collection().insert_one(user_data)
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        return User.get_collection().find_one({'email': email.lower().strip(), 'active': True})
    
    @staticmethod
    def find_by_username(username):
        """Find user by username"""
        return User.get_collection().find_one({'username': username.lower(), 'active': True})
    
    @staticmethod
    def find_by_id(user_id):
        """Find user by ID"""
        return User.get_collection().find_one({'_id': ObjectId(user_id)})
    
    @staticmethod
    def verify_password(stored_hash, password):
        """Verify password against stored hash"""
        return check_password_hash(stored_hash, password)
    
    @staticmethod
    def email_exists(email):
        """Check if email already exists"""
        return User.get_collection().find_one({'email': email.lower().strip()}) is not None
    
    @staticmethod
    def username_exists(username):
        """Check if username already exists"""
        return User.get_collection().find_one({'username': username.lower()}) is not None
    
    @staticmethod
    def count_by_role(role):
        """Count users by role"""
        return User.get_collection().count_documents({'role': role, 'active': True})
    
    @staticmethod
    def update_user(user_id, update_data):
        """Update user data"""
        update_data['updated_at'] = datetime.utcnow()
        return User.get_collection().update_one(
            {'_id': ObjectId(user_id)}, 
            {'$set': update_data}
        )
    
    @staticmethod
    def deactivate_user(user_id):
        """Soft delete user by setting active to False"""
        return User.get_collection().update_one(
            {'_id': ObjectId(user_id)}, 
            {'$set': {'active': False, 'deactivated_at': datetime.utcnow()}}
        )
    
    @staticmethod
    def get_all_users(skip=0, limit=100):
        """Get all active users with pagination"""
        return User.get_collection().find(
            {'active': True}
        ).skip(skip).limit(limit)
    
    @staticmethod
    def get_users_by_role(role, skip=0, limit=100):
        """Get users by role with pagination"""
        return User.get_collection().find(
            {'role': role.lower(), 'active': True}
        ).skip(skip).limit(limit)
    
    @staticmethod
    def update_last_login(user_id):
        """Update user's last login timestamp"""
        return User.get_collection().update_one(
            {'_id': ObjectId(user_id)}, 
            {'$set': {'last_login': datetime.utcnow()}}
        )