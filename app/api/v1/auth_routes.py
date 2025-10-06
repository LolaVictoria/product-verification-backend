"""
Authentication Routes
Handles login, registration, profile management, and email verification
"""

from flask import Blueprint, request
import logging

from app.services.auth.auth_service import auth_service, AuthError
from app.services.auth.token_service import token_service
from app.services.user.profile_service import profile_service
from app.services.onboarding_service import onboarding_service
from app.validators.auth_validator import AuthValidator
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.rate_limiting import rate_limit

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


# ===============================
# LOGIN ENDPOINTS
# ===============================
@auth_bp.route('/login', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def login():
    """
    Unified login endpoint - automatically detects user type
    Tries to authenticate against all user types
    """
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Email and password required'
            }, 400)
        
        email = data['email']
        password = data['password']
        
        # Try authenticating as each user type
        # Order: customer -> manufacturer -> admin
        
        # Try customer first (most common)
        try:
            result = auth_service.authenticate_customer(email, password)
            return response_middleware.create_cors_response({
                'success': True,
                'token': result['token'],
                'user': result['user'],
                'expires_at': result.get('expires_at')
            }, 200)
        except AuthError:
            pass  # Try next type
        
        # Try manufacturer
        try:
            result = auth_service.authenticate_manufacturer(email, password)
            return response_middleware.create_cors_response({
                'success': True,
                'token': result['token'],
                'user': result['user'],
                'expires_at': result.get('expires_at')
            }, 200)
        except AuthError:
            pass  # Try next type
        
        # Try admin
        try:
            result = auth_service.authenticate_admin(email, password)
            return response_middleware.create_cors_response({
                'success': True,
                'token': result['token'],
                'user': result['user'],
                'expires_at': result.get('expires_at')
            }, 200)
        except AuthError:
            pass  # All failed
        
        # If all authentication attempts failed
        logger.warning(f"Login failed for {email}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Invalid email or password'
        }, 401)
        
    except Exception as e:
        logger.error(f"Unified login error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Login failed'
        }, 500)
# ===============================
# REGISTRATION ENDPOINTS
# ===============================

@auth_bp.route('/register', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def register():
    """
    User registration endpoint
    Delegates to onboarding service for manufacturers, auth service for others
    """
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        # Validate registration data
        validation_result = AuthValidator.validate_registration_data(data)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }, 400)
        
        # Route to appropriate registration service
        role = data.get('role', 'customer').lower()
        
        if role == 'manufacturer':
            # Use onboarding service for B2B SaaS flow
            result = onboarding_service.register_manufacturer(data)
        else:
            # Use authentication service for customer/other roles
            result = auth_service.register_user(data)
        
        status_code = 201 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Registration failed'
        }, 500)


@auth_bp.route('/manufacturer/register', methods=['POST'])
@rate_limit({'per_minute': 3, 'per_hour': 10})
def register_manufacturer():
    """
    Dedicated manufacturer registration endpoint
    Provides instant sandbox access and trial period
    """
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        # Force role to manufacturer
        data['role'] = 'manufacturer'
        
        # Validate manufacturer-specific data
        validation_result = AuthValidator.validate_registration_data(data)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }, 400)
        
        # Use onboarding service
        result = onboarding_service.register_manufacturer(data)
        
        status_code = 201 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Manufacturer registration error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Registration failed'
        }, 500)


# ===============================
# EMAIL VERIFICATION
# ===============================

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """Verify email address using verification token"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        verification_token = data.get('token')
        
        if not verification_token:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Verification token is required'
            }, 400)
        
        # Use onboarding service for verification
        result = onboarding_service.verify_email(verification_token)
        
        status_code = 200 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Email verification error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Email verification failed'
        }, 500)


@auth_bp.route('/resend-verification', methods=['POST'])
@rate_limit({'per_minute': 2, 'per_hour': 10})
def resend_verification():
    """Resend email verification"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        email = data.get('email')
        
        if not email:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Email address is required'
            }, 400)
        
        # Validate email format
        validation_result = AuthValidator.validate_email(email)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': validation_result['errors'][0]
            }, 400)
        
        # Use onboarding service
        result = onboarding_service.resend_verification_email(email)
        
        status_code = 200 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Resend verification error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to resend verification email'
        }, 500)


# ===============================
# LOGOUT & TOKEN MANAGEMENT
# ===============================

@auth_bp.route('/logout', methods=['POST'])
@auth_middleware.require_auth
def logout(current_user_id, current_user_role):
    """User logout endpoint"""
    try:
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'No token provided'
            }, 400)
        
        token = auth_header.split(' ')[1]
        
        # Invalidate token
        result = token_service.invalidate_token(token)
        
        if result.get('success'):
            return response_middleware.create_cors_response({
                'success': True,
                'message': 'Logged out successfully'
            }, 200)
        else:
            return response_middleware.create_cors_response({
                'success': False,
                'error': result.get('error', 'Logout failed')
            }, 500)
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Logout failed'
        }, 500)


@auth_bp.route('/refresh', methods=['POST'])
@auth_middleware.require_auth
def refresh_token(current_user_id, current_user_role):
    """Refresh authentication token"""
    try:
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'No token provided'
            }, 400)
        
        old_token = auth_header.split(' ')[1]
        
        # Generate new token
        result = token_service.refresh_token(old_token)
        
        if result.get('success'):
            return response_middleware.create_cors_response({
                'success': True,
                'token': result['token'],
                'expires_at': result['expires_at']
            }, 200)
        else:
            return response_middleware.create_cors_response({
                'success': False,
                'error': result.get('error', 'Token refresh failed')
            }, 401)
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Token refresh failed'
        }, 500)


# ===============================
# TOKEN VERIFICATION
# ===============================

@auth_bp.route('/verify', methods=['GET'])
@auth_middleware.require_auth
def verify_auth(current_user_id, current_user_role):
    """Verify if token is valid"""
    return response_middleware.create_cors_response({
        'success': True,
        'valid': True,
        'user': {
            'id': current_user_id,
            'role': current_user_role
        }
    }, 200)


# ===============================
# PROFILE MANAGEMENT
# ===============================

@auth_bp.route('/profile', methods=['GET'])
@auth_middleware.token_required_with_roles(['customer', 'manufacturer', 'admin'])
def get_profile(current_user_id, current_user_role):
    """Get user profile for any role"""
    try:
        result = profile_service.get_user_profile(current_user_id, current_user_role)
        
        if not result['success']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': result.get('message', 'Profile not found')
            }, 404)
        
        return response_middleware.create_cors_response({
            'success': True,
            'user': result['profile']
        }, 200)
        
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to get profile'
        }, 500)


@auth_bp.route('/profile', methods=['PUT'])
@auth_middleware.token_required_with_roles(['customer', 'manufacturer', 'admin'])
def update_profile(current_user_id, current_user_role):
    """Update user profile"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        result = profile_service.update_user_profile(
            current_user_id, 
            current_user_role, 
            data
        )
        
        if not result['success']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': result.get('message', 'Profile update failed')
            }, 400)
        
        return response_middleware.create_cors_response({
            'success': True,
            'message': result.get('message', 'Profile updated successfully'),
            'user': result.get('profile')
        }, 200)
        
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to update profile'
        }, 500)


# ===============================
# PASSWORD MANAGEMENT
# ===============================

@auth_bp.route('/change-password', methods=['POST'])
@auth_middleware.require_auth
def change_password(current_user_id, current_user_role):
    """Change user password"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Current password and new password required'
            }, 400)
        
        # Validate new password strength
        validation_result = AuthValidator.validate_password_strength(new_password)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Password does not meet requirements',
                'errors': validation_result['errors']
            }, 400)
        
        # Change password through authentication service
        result = auth_service.change_password(
            current_user_id,
            current_password,
            new_password
        )
        
        status_code = 200 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Change password error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to change password'
        }, 500)


@auth_bp.route('/forgot-password', methods=['POST'])
@rate_limit({'per_minute': 3, 'per_hour': 10})
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        email = data.get('email')
        
        if not email:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Email is required'
            }, 400)
        
        # Validate email
        validation_result = AuthValidator.validate_email(email)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': validation_result['errors'][0]
            }, 400)
        
        result = auth_service.request_password_reset(email)
        
        # Always return success to prevent email enumeration
        return response_middleware.create_cors_response({
            'success': True,
            'message': 'If an account exists with this email, a password reset link has been sent'
        }, 200)
        
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return response_middleware.create_cors_response({
            'success': True,
            'message': 'If an account exists with this email, a password reset link has been sent'
        }, 200)


@auth_bp.route('/reset-password', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        
        if not data:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Request body required'
            }, 400)
        
        reset_token = data.get('token')
        new_password = data.get('password')
        
        if not reset_token or not new_password:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Token and new password required'
            }, 400)
        
        # Validate password strength
        validation_result = AuthValidator.validate_password_strength(new_password)
        if not validation_result['valid']:
            return response_middleware.create_cors_response({
                'success': False,
                'error': 'Password does not meet requirements',
                'errors': validation_result['errors']
            }, 400)
        
        result = auth_service.reset_password(reset_token, new_password)
        
        status_code = 200 if result.get('success') else 400
        return response_middleware.create_cors_response(result, status_code)
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Password reset failed'
        }, 500)


# ===============================
# HEALTH CHECK
# ===============================

@auth_bp.route('/health', methods=['GET'])
def health_check():
    """Auth service health check"""
    return response_middleware.create_cors_response({
        'status': 'healthy',
        'service': 'auth',
        'endpoints': {
            'login':  '/v1/auth/login',
            'register': '/v1/auth/register',
            'verify_email': '/v1/auth/verify-email',
            'profile': '/v1/auth/profile'
        }
    }, 200)