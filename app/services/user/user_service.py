# services/User_service.py
import os
from datetime import datetime, timezone
from bson import ObjectId
import logging
from dotenv import load_dotenv
import os 
from app.config.database import get_db_connection
from typing import Optional, Dict, Any
import hashlib
import secrets
from app.utils.password_utils import hash_password

load_dotenv()
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

# Mock database - replace with your actual database implementation
users_db = {}  # {user_id: user_data}
email_index = {}  # {email: user_id}
blacklisted_tokens = set()  # Set of blacklisted JWT tokens



class UserService:
    """Service for handling Userentication operations"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
    
    @staticmethod
    def register_user(self, user_data: dict) -> dict:
        """Register new user"""
        try:
            email = user_data.get('email', '').lower().strip()
            password = user_data.get('password')
            role = user_data.get('role', 'customer')
            
            # Check if user already exists
            if UserService.get_user_by_email(email):
                return {
                    'success': False,
                    'message': 'User with this email already exists'
                }
            
            # Prepare user data
            user_doc = {
                'email': email,
                'primary_email': email,
                'emails': [email],
                'password': hash_password(password),
                'role': role,
                'verification_status': 'pending',
                'is_active': True,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            # Add role-specific fields
            if role == 'manufacturer':
                user_doc.update({
                    'company_names': [user_data.get('company_name', '')],
                    'current_company_name': user_data.get('company_name', ''),
                    'wallet_addresses': [user_data.get('wallet_address')] if user_data.get('wallet_address') else [],
                    'primary_wallet': user_data.get('wallet_address'),
                    'verified_wallets': []
                })
            
            user_id = UserService.create_user(user_doc)
            
            return {
                'success': True,
                'message': 'User registered successfully',
                'user_id': user_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': 'Registration failed'
            }
    
    @staticmethod
    def create_user(email: str, password: str, **kwargs) -> Dict[str, Any]:
        """
        Create a new user with the provided information.
        
        Args:
            email (str): User's email address
            password (str): User's password (will be hashed)
            **kwargs: Additional user data (name, role, etc.)
            
        Returns:
            Dict[str, Any]: The created user data
            
        Raises:
            ValueError: If email already exists or invalid data provided
        """
        if not email or not password:
            raise ValueError("Email and password are required")
        
        email = email.lower().strip()
        
        # Check if user already exists
        if email in email_index:
            raise ValueError(f"User with email {email} already exists")
        
        # Generate user ID
        user_id = secrets.token_hex(16)
        
        # Hash password (in production, use bcrypt or similar)
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                        password.encode('utf-8'), 
                                        salt.encode('utf-8'), 
                                        100000)
        
        # Create user data
        user_data = {
            'id': user_id,
            'email': email,
            'password_hash': password_hash.hex(),
            'salt': salt,
            'created_at': datetime.datetime.now(datetime.UTC).isoformat(),
            'updated_at': datetime.datetime.now(datetime.UTC).isoformat(),
            'is_active': True,
            **kwargs  # Additional fields like name, role, etc.
        }
        
        # Store user
        users_db[user_id] = user_data
        email_index[email] = user_id
        
        # Return user data without sensitive information
        safe_user_data = user_data.copy()
        safe_user_data.pop('password_hash', None)
        safe_user_data.pop('salt', None)
        
        return safe_user_data


        def update_user(user_id: str, **kwargs) -> Optional[Dict[str, Any]]:
            """
            Update user information.
            
            Args:
                user_id (str): The user ID to update
                **kwargs: Fields to update
                
            Returns:
                Optional[Dict[str, Any]]: Updated user data if successful, None otherwise
            """
            if user_id not in users_db:
                return None
            
            # Don't allow direct updates to sensitive fields
            forbidden_fields = {'id', 'password_hash', 'salt', 'created_at'}
            update_data = {k: v for k, v in kwargs.items() if k not in forbidden_fields}
            
            if update_data:
                users_db[user_id].update(update_data)
                users_db[user_id]['updated_at'] = datetime.datetime.now(datetime.UTC).isoformat()
            
            # Return safe user data
            safe_user_data = users_db[user_id].copy()
            safe_user_data.pop('password_hash', None)
            safe_user_data.pop('salt', None)
            
            return safe_user_data


        def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
            """
            Retrieve a user by their email address.
            
            Args:
                email (str): The email address to search for
                
            Returns:
                Optional[Dict[str, Any]]: User data if found, None otherwise
            """
            if not email:
                return None
            
            email = email.lower().strip()
            user_id = email_index.get(email)
            
            if user_id and user_id in users_db:
                return users_db[user_id].copy()
            
            return None

    @staticmethod
    def get_client_ip(request) -> str:
        """Get client IP address from request"""
        return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

    @staticmethod
    def get_user_agent(request) -> str:
        """Get user agent from request"""
        return request.headers.get('User-Agent', '')

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a user by their user ID.
        
        Args:
            user_id (str): The user ID to search for
            
        Returns:
            Optional[Dict[str, Any]]: User data if found, None otherwise
        """
        if not user_id:
            return None
        
        if user_id in users_db:
            return users_db[user_id].copy()
        
        return None

    @staticmethod
    def _update_last_login(self, user_id: ObjectId):
        """Update user's last login timestamp"""
        try:
            db = get_db_connection()
            db.users.update_one(
                {'_id': user_id},
                {'$set': {'last_login': datetime.now(timezone.utc)}}
            )
        except Exception:
            pass  

    
# Singleton instanceuser_service = UserService()