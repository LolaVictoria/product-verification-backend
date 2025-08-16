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
    def create_user(email, password, role, wallet_address=None):
        """Create a new user"""
        user_data = {
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
    def count_by_role(role):
        """Count users by role"""
        return User.get_collection().count_documents({'role': role, 'active': True})
