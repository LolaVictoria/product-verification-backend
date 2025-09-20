# services/auth_service.py
import jwt
import os
from datetime import datetime, timezone, timedelta
from bson import ObjectId

from utils.database import get_db_connection
from utils.security import security_utils
from utils.users import get_user_by_email, create_user, blacklist_token
from utils.helpers import format_user_response

class AuthService:
    """Service for handling authentication operations"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
        
    def generate_token(self, user_id: str, user_role: str) -> str:
        """Generate JWT token for user"""
        payload = {
            'sub': str(user_id),
            'role': user_role,
            'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def authenticate_user(self, email: str, password: str) -> dict:
        """Authenticate user with email and password"""
        try:
            # Normalize email
            normalized_email = email.lower().strip() if email else None
            
            if not normalized_email or not password:
                return {
                    'success': False,
                    'message': 'Email and password are required'
                }
            
            # Find user
            user = get_user_by_email(normalized_email)
            if not user:
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }
            
            # Check if user is active
            if not user.get('is_active', True):
                return {
                    'success': False,
                    'message': 'Account is inactive'
                }
            
            # Verify password
            stored_hash = user.get('password_hash') or user.get('password')
            if not stored_hash:
                return {
                    'success': False,
                    'message': 'Account authentication error'
                }
            
            if not security_utils.verify_password(stored_hash, password):
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }
            
            # Generate token
            token = self.generate_token(user['_id'], user['role'])
            
            # Update last login
            self._update_last_login(user['_id'])
            
            return {
                'success': True,
                'user': format_user_response(user),
                'token': token,
                'expires_at': (datetime.utcnow() + timedelta(hours=self.token_expiry_hours)).isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': 'Authentication service error'
            }
    
    def register_user(self, user_data: dict) -> dict:
        """Register new user"""
        try:
            email = user_data.get('email', '').lower().strip()
            password = user_data.get('password')
            role = user_data.get('role', 'customer')
            
            # Check if user already exists
            if get_user_by_email(email):
                return {
                    'success': False,
                    'message': 'User with this email already exists'
                }
            
            # Prepare user data
            user_doc = {
                'email': email,
                'primary_email': email,
                'emails': [email],
                'password_hash':security_utils. hash_password(password),
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
            
            user_id = create_user(user_doc)
            
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
    
    def logout_user(self, token: str) -> dict:
        """Logout user by blacklisting token"""
        try:
            if blacklist_token(token):
                return {
                    'success': True,
                    'message': 'Logged out successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Token blacklisting failed'
                }
        except Exception as e:
            return {
                'success': False,
                'message': 'Logout failed'
            }
    
    def refresh_token(self, old_token: str) -> dict:
        """Refresh user token"""
        try:
            # Decode old token to get user info
            payload = jwt.decode(old_token, self.secret_key, algorithms=['HS256'])
            user_id = payload.get('sub')
            user_role = payload.get('role')
            
            # Generate new token
            new_token = self.generate_token(user_id, user_role)
            
            # Blacklist old token
            blacklist_token(old_token)
            
            return {
                'success': True,
                'token': new_token,
                'expires_at': (datetime.utcnow() + timedelta(hours=self.token_expiry_hours)).isoformat()
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'success': False,
                'message': 'Token has expired'
            }
        except jwt.InvalidTokenError:
            return {
                'success': False,
                'message': 'Invalid token'
            }
        except Exception as e:
            return {
                'success': False,
                'message': 'Token refresh failed'
            }
    
    def _update_last_login(self, user_id: ObjectId):
        """Update user's last login timestamp"""
        try:
            db = get_db_connection()
            db.users.update_one(
                {'_id': user_id},
                {'$set': {'last_login': datetime.now(timezone.utc)}}
            )
        except Exception:
            pass  # Non-critical operation

# Singleton instance
auth_service = AuthService()