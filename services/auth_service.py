from flask_jwt_extended import create_access_token, create_refresh_token
from models import User, ApiKey
from utils.validators import is_valid_email, is_valid_password
from utils.helpers import create_error_response, create_success_response
from utils.email_service import EmailService
import logging
import bcrypt
import secrets
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AuthService:
    @staticmethod
    def register_user(username, email, password, role, wallet_address=None, verification_token=None):
        """Register a new user with email verification"""
        try:
            # Validate input
            if not is_valid_email(email):
                return create_error_response('Invalid email format', 400)
            
            if not is_valid_password(password):
                return create_error_response('Password must be at least 8 characters long', 400)
            
            if role not in ['manufacturer', 'developer']:
                return create_error_response('Invalid role. Must be manufacturer or developer', 400)
            
            # Role-specific validation
            verification_status = 'pending'
            if role == 'manufacturer':
                # Check if wallet_address is None, empty string, or whitespace only
                if not wallet_address or not wallet_address.strip():
                    logger.error(f"Manufacturer role requires wallet address. Received: '{wallet_address}'")
                    return create_error_response('Wallet address required for manufacturers', 400)
                verification_status = 'pending'
            else:
                wallet_address = None
                verification_status = 'verified'  # Developers don't need wallet verification
            
            # Check if user already exists
            existing_user = User.find_by_email(email.lower())
            if existing_user:
                return create_error_response('User with this email already exists', 400)
            
            existing_username = User.find_by_username(username)
            if existing_username:
                return create_error_response('Username already taken', 400)
            
            # Generate verification token for email verification
            if not verification_token:
                verification_token = secrets.token_urlsafe(32)
            
            # Hash password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Create user data
            user_data = {
                'username': username,
                'email': email.lower(),
                'password': hashed_password.decode('utf-8'),
                'password_hash': hashed_password.decode('utf-8'),  # Keep both for compatibility
                'role': role.lower(),
                'wallet_address': wallet_address,
                'verification_status': verification_status,
                'is_verified': False,  # Email not verified yet
                'verification_token': verification_token,
                'verification_token_expires': datetime.utcnow() + timedelta(hours=24),  # 24 hour expiry
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'is_active': True,
                'is_admin': False
            }
            
            # Save user to database
            user_id = User.create(user_data)
            
            if user_id:
                # Send verification email
                try:
                    EmailService.send_verification_email(email.lower(), username, verification_token)
                    logger.info(f"Verification email sent to: {email}")
                except Exception as e:
                    logger.warning(f"Failed to send verification email: {str(e)}")
                
                logger.info(f"User created successfully: {username} ({email})")
                return create_success_response({
                    'user_id': str(user_id),
                    'message': 'User registered successfully. Please verify your email.',
                    'email_sent': True
                }, 201)
            else:
                return create_error_response('Failed to create user', 500)
                
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return create_error_response('Registration failed', 500)
    
    @staticmethod
    def verify_email_token(token):
        """Verify email using the verification token"""
        try:
            # Find user by verification token
            user = User.find_by_verification_token(token)
            
            if not user:
                return create_error_response('Invalid verification token', 400)
            
            # Check if token is expired
            if user.get('verification_token_expires') < datetime.utcnow():
                return create_error_response('Verification token has expired', 400)
            
            # Check if already verified
            if user.get('is_verified'):
                return create_success_response({'message': 'Email already verified'}, 200)
            
            # Update user as verified
            update_data = {
                'is_verified': True,
                'verification_token': None,  # Clear the token
                'verification_token_expires': None,
                'updated_at': datetime.utcnow()
            }
            
            success = User.update_by_id(user['_id'], update_data)
            
            if success:
                # Send welcome email (optional, non-blocking)
                try:
                    EmailService.send_welcome_email(user['email'], user['username'])
                except Exception as e:
                    logger.warning(f"Failed to send welcome email: {str(e)}")
                
                logger.info(f"Email verified successfully for user: {user['email']}")
                return create_success_response({
                    'message': 'Email verified successfully',
                    'user_id': str(user['_id']),
                    'verified': True
                }, 200)
            else:
                return create_error_response('Failed to update verification status', 500)
                
        except Exception as e:
            logger.error(f"Email verification error: {str(e)}")
            return create_error_response('Verification failed', 500)
    
    @staticmethod
    def resend_verification_email(email):
        """Resend verification email"""
        try:
            user = User.find_by_email(email.lower())
            
            if not user:
                return create_error_response('User not found', 404)
            
            if user.get('is_verified'):
                return create_error_response('Email already verified', 400)
            
            # Generate new verification token
            verification_token = secrets.token_urlsafe(32)
            
            # Update user with new token
            update_data = {
                'verification_token': verification_token,
                'verification_token_expires': datetime.utcnow() + timedelta(hours=24),
                'updated_at': datetime.utcnow()
            }
            
            success = User.update_by_id(user['_id'], update_data)
            
            if success:
                # Send verification email
                EmailService.send_verification_email(email.lower(), user['username'], verification_token)
                
                logger.info(f"Verification email resent to: {email}")
                return create_success_response({
                    'message': 'Verification email sent',
                    'email_sent': True
                }, 200)
            else:
                return create_error_response('Failed to update verification token', 500)
                
        except Exception as e:
            logger.error(f"Resend verification error: {str(e)}")
            return create_error_response('Failed to resend verification email', 500)
    
    @staticmethod
    def authenticate_user(email, password):
        """Authenticate user and return access token"""
        try:
            # Validate input
            if not email or not password:
                return create_error_response('Email and password required', 400)
            
            user = User.find_by_email(email.lower())
            
            if not user:
                return create_error_response('Invalid email or password', 401)
            
            # Check if email is verified
            if not user.get('is_verified', False):
                return create_error_response('Please verify your email address before logging in', 401)
            
            # Check if account is active
            if not user.get('is_active', True):
                return create_error_response('Account is deactivated', 401)
            
            # Verify password - handle both password fields for compatibility
            password_field = user.get('password') or user.get('password_hash')
            if not password_field:
                return create_error_response('Invalid account configuration', 500)
            
            if not bcrypt.checkpw(password.encode('utf-8'), password_field.encode('utf-8')):
                return create_error_response('Invalid email or password', 401)
            
            # Create tokens with comprehensive claims
            additional_claims = {
                'role': user['role'],
                'user_id': str(user['_id']),
                'username': user['username'],
                'is_verified': user.get('is_verified', False),
                'is_admin': user.get('is_admin', False),
                'verification_status': user.get('verification_status', 'pending')
            }
            
            access_token = create_access_token(
                identity=str(user['_id']),
                additional_claims=additional_claims
            )
            
            refresh_token = create_refresh_token(identity=str(user['_id']))
            
            # Prepare comprehensive user data for response (exclude sensitive info)
            user_data = {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'wallet_address': user.get('wallet_address'),
                'verification_status': user.get('verification_status', 'pending'),
                'is_verified': user.get('is_verified', False),
                'is_admin': user.get('is_admin', False),
                'is_active': user.get('is_active', True),
                'created_at': user['created_at'].isoformat() if user.get('created_at') else None
            }
            
            logger.info(f"User authenticated successfully: {email}")
            
            return create_success_response({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user_data,
                'authenticated': True
            }, 200)
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return create_error_response('Authentication failed', 500)
    
    @staticmethod
    def get_user_profile(user_id):
        """Get user profile information"""
        try:
            user = User.find_by_id(user_id)
            
            if not user:
                return create_error_response('User not found', 404)
            
            # Prepare comprehensive user data (exclude sensitive info)
            user_data = {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'wallet_address': user.get('wallet_address'),
                'verification_status': user.get('verification_status', 'pending'),
                'is_verified': user.get('is_verified', False),
                'is_admin': user.get('is_admin', False),
                'is_active': user.get('is_active', True),
                'created_at': user['created_at'].isoformat() if user.get('created_at') else None,
                'updated_at': user['updated_at'].isoformat() if user.get('updated_at') else None
            }
            
            return create_success_response({
                'user': user_data,
                'profile_loaded': True
            }, 200)
            
        except Exception as e:
            logger.error(f"Get profile error: {str(e)}")
            return create_error_response('Failed to get user profile', 500)
    
    @staticmethod
    def verify_api_key(api_key, request_info):
        """Verify API key and log usage"""
        try:
            key_doc = ApiKey.find_by_key(api_key)
            if not key_doc:
                logger.warning(f"Invalid API key used: {api_key[:8]}...")
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
            
            logger.info(f"API key verified for user: {key_doc['user_id']}")
            return key_doc
            
        except Exception as e:
            logger.error(f"API key verification error: {str(e)}")
            return None
    
    @staticmethod
    def update_user_profile(user_id, update_data):
        """Update user profile information"""
        try:
            # Filter allowed update fields
            allowed_fields = ['username', 'wallet_address']
            filtered_data = {k: v for k, v in update_data.items() if k in allowed_fields}
            
            if not filtered_data:
                return create_error_response('No valid fields to update', 400)
            
            # Add update timestamp
            filtered_data['updated_at'] = datetime.utcnow()
            
            success = User.update_by_id(user_id, filtered_data)
            
            if success:
                logger.info(f"Profile updated for user: {user_id}")
                return create_success_response({
                    'message': 'Profile updated successfully',
                    'updated': True
                }, 200)
            else:
                return create_error_response('Failed to update profile', 500)
                
        except Exception as e:
            logger.error(f"Profile update error: {str(e)}")
            return create_error_response('Profile update failed', 500)