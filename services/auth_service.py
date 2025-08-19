from flask_jwt_extended import create_access_token
from models import User, ApiKey
from utils.validators import is_valid_email, is_valid_password
import logging

logger = logging.getLogger(__name__)

class AuthService:
    @staticmethod
    def register_user(username, email, password, role, wallet_address):
        """Register a new user"""
        # Validate input
        if not is_valid_email(email):
            return {'error': 'Invalid email format'}, 400
        
        if not is_valid_password(password):
            return {'error': 'Password must be at least 8 characters long'}, 400
        
        if role not in ['manufacturer', 'developer']:
            return {'error': 'Invalid role. Must be manufacturer or developer'}, 400
        
        if role == 'manufacturer':
            # Check if wallet_address is None, empty string, or whitespace only
            if not wallet_address or not wallet_address.strip():
                logger.error(f"Manufacturer role requires wallet address. Received: '{wallet_address}'")
                return {'error': 'Wallet address required for manufacturers'}, 400
    
        # Check if user already exists
        if User.email_exists(email):
            return {'error': 'Email already registered'}, 400
        
        # Check if username already exists
        if User.username_exists(username):
            return {'error': 'Username already exists'}, 400
        
        
        try:
            result = User.create_user(username, email, password, role, wallet_address)
            return {
                'message': 'User created successfully',
                'user_id': str(result.inserted_id)
            }, 201
        except Exception as e:
            logger.error(f"User registration error: {e}")
            return {'error': 'Registration failed'}, 500
    
    @staticmethod
    def authenticate_user(email, password):
        """Authenticate user and return access token"""
        if not email or not password:
            return {'error': 'Email and password required'}, 400
        
        user = User.find_by_email(email)
        if not user or not User.verify_password(user['password_hash'], password):
            return {'error': 'Invalid credentials'}, 401
        
        try:
            # Create JWT token with user info
            additional_claims = {
                'role': user['role'],
                'user_id': str(user['_id']),
                'username': user['username']
            }
            access_token = create_access_token(
                identity=str(user['_id']),
                additional_claims=additional_claims
            )
            
            return {
                'access_token': access_token,
                'user': {
                    'id': str(user['_id']),
                    'email': user['email'],
                    'role': user['role'],
                    'username': user['username'],
                    'wallet_address': user.get('wallet_address', '')
                }
            }, 200
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {'error': 'Authentication failed'}, 500
    
    
    
    @staticmethod
    def get_user_profile(user_id):
        """Get user profile information"""
        try:
            user = User.find_by_id(user_id)
            if not user:
                return {'error': 'User not found'}, 404
            
            return {
                'user': {
                    'id': str(user['_id']),
                    'email': user['email'],
                    'username': user['username'],
                    'role': user['role'],
                    'wallet_address': user.get('wallet_address', ''),
                    'created_at': user['created_at'].isoformat()
                }
            }, 200
        except Exception as e:
            logger.error(f"Profile retrieval error: {e}")
            return {'error': 'Failed to retrieve profile'}, 500
    
    @staticmethod
    def verify_api_key(api_key, request_info):
        """Verify API key and log usage"""
        key_doc = ApiKey.find_by_key(api_key)
        if not key_doc:
            return None
        
        # Update usage statistics
        ApiKey.update_usage(key_doc['_id'])
        
        # Log API usage
        ApiKey.log_usage(
            key_doc['_id'],
            key_doc['user_id'],
            request_info.get('endpoint'),
            request_info.get('ip'),
            request_info.get('user_agent', '')
        )
        
        return key_doc
    
    # Add these methods to your AuthService class

@staticmethod
def get_pending_manufacturers():
    """Get all manufacturers with pending blockchain verification"""
    try:
        # Query your database for users with role='manufacturer' and blockchain_status='pending_verification'
        # This depends on your database implementation
        # Example with SQLAlchemy:
        # users = User.query.filter_by(role='manufacturer', blockchain_status='pending_verification').all()
        # return [{'user_id': u.id, 'wallet_address': u.wallet_address} for u in users]
        
        # Placeholder - implement based on your database
        pass
    except Exception as e:
        logger.error(f"Error getting pending manufacturers: {e}")
        return []

@staticmethod
def update_manufacturers_blockchain_status(wallet_addresses, status):
    """Update blockchain status for multiple manufacturers"""
    try:
        # Update your database to set blockchain_status='verified' for these addresses
        # Example with SQLAlchemy:
        # User.query.filter(User.wallet_address.in_(wallet_addresses)).update(
        #     {'blockchain_status': status}, synchronize_session=False
        # )
        # db.session.commit()
        
        # Placeholder - implement based on your database
        pass
    except Exception as e:
        logger.error(f"Error updating manufacturer status: {e}")

