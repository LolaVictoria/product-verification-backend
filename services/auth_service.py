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
    email_exists_globally, wallet_exists_globally, is_valid_email, 
    is_valid_wallet_address, send_email_verification, get_current_utc
)

class AuthService:
    """Authentication service handling login, registration, and token management"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
        self.reset_token_expiry_hours = int(os.getenv('RESET_TOKEN_EXPIRY_HOURS', '1'))
        
    def authenticate_user(self, email, password):
        """Authenticate user login"""
        try:
            if not email or not password:
                return {'success': False, 'message': 'Email and password are required'}
            
            # Get user from database
            user = get_user_by_email(email.lower())
            if not user:
                return {'success': False, 'message': 'Invalid credentials'}
            
            # Verify password
            if not verify_password(user['password_hash'], password):
                return {'success': False, 'message': 'Invalid credentials'}
            
            # Generate JWT token
            token_data = {
                'sub': str(user['_id']),
                'role': user['role'],
                'email': user['primary_email'],
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=self.token_expiry_hours)
            }
            
            token = jwt.encode(token_data, self.secret_key, algorithm='HS256')
            
            # Update last login
            db = get_db_connection()
            db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': get_current_utc()}}
            )
            
            return {
                'success': True,
                'token': token,
                'user': user,
                'expires_at': token_data['exp'].isoformat()
            }
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return {'success': False, 'message': 'Authentication failed'}
    
    def register_user(self, user_data):
        """Register new user"""
        try:
            email = user_data.get('email', '').lower()
            password = user_data.get('password')
            role = user_data.get('role')
            
            # Basic validation
            if not all([email, password, role]):
                return {'success': False, 'message': 'Email, password, and role are required'}
            
            if role not in ['manufacturer', 'customer']:
                return {'success': False, 'message': 'Invalid role specified'}
            
            # Check if user already exists
            if get_user_by_email(email):
                return {'success': False, 'message': 'User with this email already exists'}
            
            # Prepare user data
            new_user_data = {
                'emails': [email],
                'primary_email': email,
                'password_hash': hash_password(password),
                'role': role,
                'created_at': get_current_utc(),
                'updated_at': get_current_utc(),
                'email_verified': False,
                'last_login': None
            }
            
            # Role-specific data
            if role == 'manufacturer':
                wallet_address = user_data.get('wallet_address')
                company_name = user_data.get('company_name')
                
                if not wallet_address or not company_name:
                    return {'success': False, 'message': 'Wallet address and company name are required for manufacturers'}
                
                if not is_valid_wallet_address(wallet_address):
                    return {'success': False, 'message': 'Invalid wallet address format'}
                
                if wallet_exists_globally(wallet_address):
                    return {'success': False, 'message': 'Wallet address already registered'}
                
                new_user_data.update({
                    'wallet_addresses': [wallet_address],
                    'primary_wallet': wallet_address,
                    'verified_wallets': [],
                    'company_names': [company_name],
                    'current_company_name': company_name,
                    'verification_status': 'pending',
                    'wallet_verified': False
                })
            
            # Create user
            user_id = create_user(new_user_data)
            
            # Get created user
            created_user = get_user_by_id(user_id)
            
            # Send email verification (optional, don't fail registration if it fails)
            try:
                send_email_verification(created_user)
            except Exception as e:
                print(f"Email verification sending failed: {e}")
            
            return {
                'success': True,
                'user_id': str(user_id),
                'user': created_user,
                'message': 'User registered successfully'
            }
            
        except Exception as e:
            print(f"Registration error: {e}")
            return {'success': False, 'message': 'Registration failed'}
    
    def verify_token(self, token):
        """Verify JWT token validity"""
        try:
            if not token:
                return {'valid': False, 'message': 'No token provided'}
            
            # Check if token is blacklisted
            db = get_db_connection()
            if db.blacklisted_tokens.find_one({'token': token}):
                return {'valid': False, 'message': 'Token has been revoked'}
            
            # Decode and verify token
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            user_id = payload.get('sub')
            
            # Get current user data
            user = get_user_by_id(ObjectId(user_id))
            if not user:
                return {'valid': False, 'message': 'User not found'}
            
            return {
                'valid': True,
                'user': user,
                'payload': payload,
                'expires_at': datetime.fromtimestamp(payload['exp']).isoformat()
            }
            
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'message': 'Token has expired'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'message': 'Invalid token'}
        except Exception as e:
            print(f"Token verification error: {e}")
            return {'valid': False, 'message': 'Token verification failed'}
    
    def refresh_token(self, old_token):
        """Refresh authentication token"""
        try:
            # Verify current token (allow expired tokens for refresh)
            try:
                payload = jwt.decode(old_token, self.secret_key, algorithms=['HS256'],
                                   options={"verify_exp": False})
            except jwt.InvalidTokenError:
                return {'success': False, 'message': 'Invalid token'}
            
            # Check if token is blacklisted
            db = get_db_connection()
            if db.blacklisted_tokens.find_one({'token': old_token}):
                return {'success': False, 'message': 'Token has been revoked'}
            
            user_id = payload.get('sub')
            user = get_user_by_id(ObjectId(user_id))
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            # Blacklist old token
            blacklist_token(old_token)
            
            # Generate new token
            new_token_data = {
                'sub': str(user['_id']),
                'role': user['role'],
                'email': user['primary_email'],
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=self.token_expiry_hours)
            }
            
            new_token = jwt.encode(new_token_data, self.secret_key, algorithm='HS256')
            
            return {
                'success': True,
                'token': new_token,
                'expires_at': new_token_data['exp'].isoformat()
            }
            
        except Exception as e:
            print(f"Token refresh error: {e}")
            return {'success': False, 'message': 'Token refresh failed'}
    
    def change_password(self, token, current_password, new_password):
        """Change user password"""
        try:
            # Verify token
            token_result = self.verify_token(token)
            if not token_result['valid']:
                return {'success': False, 'message': token_result['message']}
            
            user = token_result['user']
            
            # Verify current password
            if not verify_password(user['password_hash'], current_password):
                return {'success': False, 'message': 'Current password is incorrect'}
            
            # Validate new password
            if len(new_password) < 8:
                return {'success': False, 'message': 'New password must be at least 8 characters long'}
            
            # Hash new password
            new_password_hash = hash_password(new_password)
            
            # Update password in database
            db = get_db_connection()
            result = db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'password_hash': new_password_hash,
                        'updated_at': get_current_utc()
                    }
                }
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'Password update failed'}
            
            return {'success': True, 'message': 'Password changed successfully'}
            
        except Exception as e:
            print(f"Password change error: {e}")
            return {'success': False, 'message': 'Password change failed'}
    
    def initiate_password_reset(self, email):
        """Initiate password reset process"""
        try:
            user = get_user_by_email(email.lower())
            if not user:
                # Don't reveal if email doesn't exist
                return {'success': True, 'message': 'Reset instructions sent if email exists'}
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_expires = get_current_utc() + timedelta(hours=self.reset_token_expiry_hours)
            
            # Store reset token
            db = get_db_connection()
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'reset_token': reset_token,
                        'reset_token_expires': reset_expires,
                        'updated_at': get_current_utc()
                    }
                }
            )
            
            # Send reset email (implement according to your email service)
            try:
                self._send_password_reset_email(user['primary_email'], reset_token)
            except Exception as e:
                print(f"Failed to send reset email: {e}")
            
            return {'success': True, 'message': 'Reset instructions sent if email exists'}
            
        except Exception as e:
            print(f"Password reset initiation error: {e}")
            return {'success': True, 'message': 'Reset instructions sent if email exists'}
    
    def reset_password(self, reset_token, new_password):
        """Reset password using reset token"""
        try:
            if not reset_token or not new_password:
                return {'success': False, 'message': 'Reset token and new password are required'}
            
            # Validate new password
            if len(new_password) < 8:
                return {'success': False, 'message': 'Password must be at least 8 characters long'}
            
            # Find user with valid reset token
            db = get_db_connection()
            user = db.users.find_one({
                'reset_token': reset_token,
                'reset_token_expires': {'$gt': get_current_utc()}
            })
            
            if not user:
                return {'success': False, 'message': 'Invalid or expired reset token'}
            
            # Hash new password
            new_password_hash = hash_password(new_password)
            
            # Update password and clear reset token
            result = db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'password_hash': new_password_hash,
                        'updated_at': get_current_utc()
                    },
                    '$unset': {
                        'reset_token': '',
                        'reset_token_expires': ''
                    }
                }
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'Password reset failed'}
            
            return {'success': True, 'message': 'Password reset successfully'}
            
        except Exception as e:
            print(f"Password reset error: {e}")
            return {'success': False, 'message': 'Password reset failed'}
    
    def validate_reset_token(self, reset_token):
        """Validate password reset token"""
        try:
            if not reset_token:
                return {'valid': False, 'message': 'Reset token is required'}
            
            db = get_db_connection()
            user = db.users.find_one({
                'reset_token': reset_token,
                'reset_token_expires': {'$gt': get_current_utc()}
            })
            
            if not user:
                return {'valid': False, 'message': 'Invalid or expired reset token'}
            
            return {
                'valid': True,
                'email': user['primary_email'],
                'message': 'Reset token is valid'
            }
            
        except Exception as e:
            print(f"Reset token validation error: {e}")
            return {'valid': False, 'message': 'Token validation failed'}
    
    def verify_manufacturer_wallet(self, token, wallet_address, signature, message):
        """Verify manufacturer wallet ownership through signature"""
        try:
            # Verify token
            token_result = self.verify_token(token)
            if not token_result['valid']:
                return {'success': False, 'message': token_result['message']}
            
            user = token_result['user']
            
            if user['role'] != 'manufacturer':
                return {'success': False, 'message': 'Only manufacturers can verify wallets'}
            
            # Validate wallet address format
            if not is_valid_wallet_address(wallet_address):
                return {'success': False, 'message': 'Invalid wallet address format'}
            
            # Check if wallet is already verified by another user
            if wallet_exists_globally(wallet_address, user['_id']):
                return {'success': False, 'message': 'Wallet address already registered to another account'}
            
            # Verify signature using Web3
            try:
                w3 = Web3()
                message_hash = w3.keccak(text=message)
                recovered_address = w3.eth.account.recover_message(message_hash, signature=signature)
                
                if recovered_address.lower() != wallet_address.lower():
                    return {'success': False, 'message': 'Signature verification failed'}
                    
            except Exception as e:
                print(f"Signature verification error: {e}")
                return {'success': False, 'message': 'Signature verification failed'}
            
            # Update user with verified wallet
            db = get_db_connection()
            current_wallets = user.get('wallet_addresses', [])
            verified_wallets = user.get('verified_wallets', [])
            
            # Add wallet if not already present
            if wallet_address not in current_wallets:
                current_wallets.append(wallet_address)
            
            # Mark as verified
            if wallet_address not in verified_wallets:
                verified_wallets.append(wallet_address)
            
            # Set as primary if no primary wallet exists
            primary_wallet = user.get('primary_wallet')
            if not primary_wallet:
                primary_wallet = wallet_address
            
            result = db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'wallet_addresses': current_wallets,
                        'verified_wallets': verified_wallets,
                        'primary_wallet': primary_wallet,
                        'wallet_verified': True,
                        'updated_at': get_current_utc()
                    }
                }
            )
            
            if result.modified_count == 0:
                return {'success': False, 'message': 'Wallet verification update failed'}
            
            # Get updated user
            updated_user = get_user_by_id(user['_id'])
            
            return {
                'success': True,
                'user': updated_user,
                'message': 'Wallet verified successfully'
            }
            
        except Exception as e:
            print(f"Wallet verification error: {e}")
            return {'success': False, 'message': 'Wallet verification failed'}
    
    def request_manufacturer_verification(self, token, verification_data):
        """Request manufacturer account verification by admin"""
        try:
            # Verify token
            token_result = self.verify_token(token)
            if not token_result['valid']:
                return {'success': False, 'message': token_result['message']}
            
            user = token_result['user']
            
            if user['role'] != 'manufacturer':
                return {'success': False, 'message': 'Only manufacturers can request verification'}
            
            if user.get('verification_status') == 'verified':
                return {'success': False, 'message': 'Account is already verified'}
            
            # Validate required verification data
            required_fields = ['business_license', 'business_address', 'contact_phone']
            missing_fields = [field for field in required_fields if not verification_data.get(field)]
            
            if missing_fields:
                return {'success': False, 'message': f'Missing required fields: {", ".join(missing_fields)}'}
            
            # Create verification request
            db = get_db_connection()
            verification_request = {
                'user_id': user['_id'],
                'email': user['primary_email'],
                'company_name': user.get('current_company_name'),
                'business_license': verification_data['business_license'],
                'business_address': verification_data['business_address'],
                'contact_phone': verification_data['contact_phone'],
                'additional_documents': verification_data.get('additional_documents', []),
                'status': 'pending',
                'submitted_at': get_current_utc(),
                'created_at': get_current_utc()
            }
            
            result = db.verification_requests.insert_one(verification_request)
            
            # Update user status
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'verification_status': 'review_pending',
                        'updated_at': get_current_utc()
                    }
                }
            )
            
            return {
                'success': True,
                'request_id': str(result.inserted_id),
                'message': 'Verification request submitted successfully'
            }
            
        except Exception as e:
            print(f"Manufacturer verification request error: {e}")
            return {'success': False, 'message': 'Verification request failed'}
    
    def _send_password_reset_email(self, email, reset_token):
        """Send password reset email (implement based on your email service)"""
        # This would integrate with your email service (SendGrid, AWS SES, etc.)
        # For now, just log the reset token
        print(f"Password reset token for {email}: {reset_token}")
        # TODO: Implement actual email sending

auth_service = AuthService()