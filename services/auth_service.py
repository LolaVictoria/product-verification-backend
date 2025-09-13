import jwt
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from web3 import Web3
import os

from utils.helper_functions import (
    get_db_connection, get_user_by_email, get_user_by_id, create_user, 
    hash_password, verify_password, blacklist_token, 
    get_user_by_email, wallet_exists_globally, verify_password, 
    is_valid_wallet_address, send_email_verification, get_current_utc
)

class AuthService:
    """Authentication service handling login, registration, and token management"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
        self.reset_token_expiry_hours = int(os.getenv('RESET_TOKEN_EXPIRY_HOURS', '1'))
    
    def generate_token(self, user_id, user_role):  # Add user_role parameter
        payload = {
            'sub': str(user_id),          # Change 'user_id' to 'sub'
            'role': user_role,            # Add role field
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')  # Use SECRET_KEY not JWT_SECRET_KEY
    def authenticate_user(self, email: str, password: str) -> dict:
        """Enhanced authenticate_user with debugging"""
        try:
            print(f"🔍 Authenticating user: '{email}'")
            
            # Normalize email
            normalized_email = email.lower().strip() if email else None
            print(f"🔍 Normalized email: '{normalized_email}'")
            
            if not normalized_email or not password:
                print("❌ Missing email or password")
                return {
                    'success': False,
                    'message': 'Email and password are required'
                }
            
            # Try to find user by email - use helper function (NO self.)
            print(f"🔍 Looking up user in database...")
            user = get_user_by_email(normalized_email)  # ← Removed self.
            
            if not user:
                print(f"❌ User not found for email: '{normalized_email}'")
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }
            
            print(f"✅ User found: {user.get('_id')} | Email: {user.get('primary_email')}")
            print(f"🔍 User verification status: {user.get('is_verified', False)}")
            print(f"🔍 User active status: {user.get('is_active', True)}")
            
            # Check if user is active
            if not user.get('is_active', True):
                print("❌ User account is inactive")
                return {
                    'success': False,
                    'message': 'Account is inactive'
                }
            
            # Verify password - use helper function (NO self.)
            print("🔍 Verifying password...")
            stored_hash = user.get('password_hash') or user.get('password')
            
            if not stored_hash:
                print("❌ No password hash stored for user")
                return {
                    'success': False,
                    'message': 'Account authentication error'
                }
            
            print(f"🔍 Stored hash exists: {bool(stored_hash)}")
            print(f"🔍 Stored hash preview: {stored_hash[:50]}..." if len(stored_hash) > 50 else f"🔍 Stored hash: {stored_hash}")
            
            is_password_valid = verify_password(stored_hash, password)  # ← Removed self.
            print(f"🔍 Password verification result: {is_password_valid}")
            
            if not is_password_valid:
                print("❌ Password verification failed")
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }
            
            print("✅ Password verified successfully")
            
            # Generate token using class method (keep self.)
            print("🔍 Generating JWT token...")
            token = self.generate_token(user['_id'], user['role']) 
            
            if not token:
                print("❌ Failed to generate token")
                return {
                    'success': False,
                    'message': 'Failed to generate authentication token'
                }
            
            print("✅ Token generated successfully")
            
            # Return successful result
            return {
                'success': True,
                'user': user,
                'token': token,
                'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
            }
            
        except Exception as e:
            print(f"❌ Authentication exception: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'message': 'Authentication service error'
            }
        
auth_service = AuthService()