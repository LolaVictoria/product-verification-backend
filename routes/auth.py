from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from services.auth_service import AuthService
from utils.helpers import create_error_response, create_success_response
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


auth_bp.route('/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    try:
        # Add detailed logging
        logger.info("Registration endpoint called")
        
        data = request.get_json()
        logger.info(f"Received data keys: {list(data.keys()) if data else 'No data'}")
        
        # Check if data is None
        if data is None:
            logger.error("No JSON data received")
            return jsonify(create_error_response("No data received", 400)), 400
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'role']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            logger.error(f"Missing fields: {missing_fields}")
            return jsonify(create_error_response(f"Missing required fields: {', '.join(missing_fields)}", 400)), 400
        
        # Extract data with additional null checks
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        
        # Check for None values before calling strip()
        if not username or not email or not password or not role:
            logger.error(f"Null values detected - username: {username}, email: {email}, password: {'***' if password else None}, role: {role}")
            return jsonify(create_error_response("Invalid data format", 400)), 400
        
        # Now safely strip
        username = username.strip()
        email = email.strip()
        role = role.strip().lower()
        wallet_address = data.get('wallet_address', '').strip() if data.get('wallet_address') else None
        
        logger.info(f"Processing registration for username: {username}, email: {email}, role: {role}")
        
        # Additional validation
        if len(username) < 3:
            return jsonify(create_error_response('Username must be at least 3 characters long', 400)), 400
        if len(username) > 50:
            return jsonify(create_error_response('Username must be less than 50 characters', 400)), 400
        
        # Add email validation
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify(create_error_response('Invalid email format', 400)), 400
        
        # Add password validation
        if len(password) < 6:
            return jsonify(create_error_response('Password must be at least 6 characters long', 400)), 400
        
        # Validate role
        valid_roles = ['manufacturer', 'consumer', 'admin']  # Add your valid roles
        if role not in valid_roles:
            return jsonify(create_error_response(f'Invalid role. Must be one of: {", ".join(valid_roles)}', 400)), 400
        
        logger.info("About to call AuthService.register_user")
        
        # Call auth service with additional error handling
        try:
            result, status_code = AuthService.register_user(
                username=username,
                email=email,
                password=password,
                role=role,
                wallet_address=wallet_address
            )
            logger.info(f"AuthService.register_user returned - Status: {status_code}")
            logger.info(f"Result type: {type(result)}, Result: {result}")
            
        except Exception as auth_error:
            logger.error(f"AuthService.register_user error: {str(auth_error)}")
            logger.error(f"AuthService error type: {type(auth_error)}")
            import traceback
            logger.error(f"AuthService traceback: {traceback.format_exc()}")
            return jsonify(create_error_response('Authentication service error', 500)), 500
        
        logger.info(f"Signup attempt for {email} - Status: {status_code}")
        return jsonify(result), status_code
        
    except AttributeError as e:
        logger.error(f"AttributeError in signup: {str(e)}")
        logger.error(f"This usually indicates calling strip() on None or accessing missing attributes")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify(create_error_response('Invalid data format', 400)), 400
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify(create_error_response('Registration failed', 500)), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('email') or not data.get('password'):
            return jsonify(create_error_response('Email and password are required', 400)), 400
        
        email = data.get('email').strip()
        password = data.get('password')
        
        # Call auth service
        result, status_code = AuthService.authenticate_user(email, password)
        
        # Log the attempt (don't log sensitive data in production)
        if status_code == 200:
            logger.info(f"Successful login for {email}")
        else:
            logger.warning(f"Failed login attempt for {email}")
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify(create_error_response('Login failed', 500)), 500

@auth_bp.route('/verify-email/<token>', methods=['GET', 'POST'])
def verify_email(token):
    """Email verification endpoint"""
    try:
        result, status_code = AuthService.verify_email_token(token)
        
        logger.info(f"Email verification attempt with token: {token[:8]}... - Status: {status_code}")
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        return jsonify(create_error_response('Email verification failed', 500)), 500

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('email'):
            return jsonify(create_error_response('Email is required', 400)), 400
        
        email = data.get('email').strip()
        
        result, status_code = AuthService.resend_verification_email(email)
        
        logger.info(f"Resend verification request for {email} - Status: {status_code}")
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Resend verification error: {str(e)}")
        return jsonify(create_error_response('Failed to resend verification email', 500)), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile endpoint"""
    try:
        user_id = get_jwt_identity()
        
        result, status_code = AuthService.get_user_profile(user_id)
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify(create_error_response('Failed to get profile', 500)), 500

@auth_bp.route('/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile endpoint"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify(create_error_response('No data provided', 400)), 400
        
        result, status_code = AuthService.update_user_profile(user_id, data)
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        return jsonify(create_error_response('Failed to update profile', 500)), 500

@auth_bp.route('/check-token', methods=['GET'])
@jwt_required()
def check_token():
    """Check if JWT token is valid"""
    try:
        user_id = get_jwt_identity()
        claims = get_jwt()
        
        return jsonify(create_success_response({
            'valid': True,
            'user_id': user_id,
            'role': claims.get('role'),
            'username': claims.get('username'),
            'is_verified': claims.get('is_verified', False),
            'verification_status': claims.get('verification_status', 'pending')
        }, 200)), 200
        
    except Exception as e:
        logger.error(f"Token check error: {str(e)}")
        return jsonify(create_error_response('Invalid token', 401)), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh JWT token endpoint"""
    try:
        from flask_jwt_extended import create_access_token, get_jwt
        
        current_user = get_jwt_identity()
        if not current_user:
            response, status_code = create_error_response('Invalid refresh token', 401)
            return jsonify(response), status_code
        
        claims = get_jwt()
        
        # Create new access token
        new_token = create_access_token(
            identity=current_user,
            additional_claims={
                'role': claims.get('role'),
                'user_id': claims.get('user_id')
            }
        )
        
        logger.info(f"Token refreshed for user: {current_user}")
        
        return jsonify({'access_token': new_token}), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Token refresh failed', 500)
        return jsonify(response), status_code

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout endpoint (client-side token removal)"""
    try:
        user_id = get_jwt_identity()
        
        # In a production app, you might want to blacklist the token
        # For now, we'll just log the logout
        logger.info(f"User {user_id} logged out")
        
        return jsonify(create_success_response({
            'message': 'Logged out successfully',
            'logged_out': True
        }, 200)), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify(create_error_response('Logout failed', 500)), 500

#admin can search for user by their id
@auth_bp.route('/users/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(user_id):
    """Fetch user by ID (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get current user profile
        current_user, status = AuthService.get_user_profile(current_user_id)
        if status != 200:
            return jsonify(create_error_response('Unable to get current user profile', 400)[0]), 400
        
        # Check if requester is admin
        if not current_user.get('user', {}).get('is_admin', False):
            return jsonify(create_error_response('Admin access required', 403)[0]), 403
        
        # Fetch the target user by ID
        target_user, status = AuthService.get_user_profile(user_id)
        return jsonify(target_user), status
        
    except Exception as e:
        logger.error(f"Get user by ID error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code


# Error handlers
@auth_bp.errorhandler(400)
def bad_request(error):
    return jsonify(create_error_response('Bad request', 400)), 400

@auth_bp.errorhandler(401)
def unauthorized(error):
    return jsonify(create_error_response('Unauthorized', 401)), 401

@auth_bp.errorhandler(404)
def not_found(error):
    return jsonify(create_error_response('Not found', 404)), 404

@auth_bp.errorhandler(500)
def internal_error(error):
    return jsonify(create_error_response('Internal server error', 500)), 500