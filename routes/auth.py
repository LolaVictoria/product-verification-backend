from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services import AuthService, BlockchainService
from utils.helpers import create_error_response, create_success_response
from utils.email_service import EmailService
import logging
import secrets

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """User registration endpoint - optimized for real-world use"""
    
    try:
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data in request")
            response, status_code = create_error_response('No data provided', 400)
            return jsonify(response), status_code
        
        # Get and validate required fields
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        wallet_address = data.get('wallet_address') or data.get('walletAddress')
        
        # Validate basic required fields
        required_fields = {
            'username': username,
            'email': email,
            'password': password,
            'role': role
        }
        
        # Add wallet_address to required fields if role is manufacturer
        if role and role.lower() == 'manufacturer':
            required_fields['wallet_address'] = wallet_address
        
        for field_name, field_value in required_fields.items():
            if not field_value or not str(field_value).strip():
                logger.error(f"Missing required field: {field_name}")
                response, status_code = create_error_response(f'{field_name} is required', 400)
                return jsonify(response), status_code
        
        # Validate role
        if role.lower() not in ['developer', 'manufacturer']:
            logger.error(f"Invalid role: {role}")
            response, status_code = create_error_response('Invalid role. Must be "developer" or "manufacturer"', 400)
            return jsonify(response), status_code
        
        # Validate wallet address format for manufacturers
        if role.lower() == 'manufacturer' and wallet_address:
            try:
                from web3 import Web3
                Web3.to_checksum_address(wallet_address)  # This validates the format
            except Exception as e:
                logger.error(f"Invalid wallet address format: {wallet_address}")
                response, status_code = create_error_response('Invalid wallet address format', 400)
                return jsonify(response), status_code
        
        logger.info("All validations passed, creating user account")
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Create user account with verification token
        result, status_code = AuthService.register_user(
            username, email, password, role, wallet_address, verification_token
        )
        
        if status_code == 201:
            try:
                # Send verification email
                EmailService.send_verification_email(email, username, verification_token)
                
                result['message'] = 'Account created successfully. Please check your email to verify your account.'
                result['email_sent'] = True
                
                if role.lower() == 'manufacturer':
                    result['blockchain_status'] = 'pending_verification'
                    result['note'] = 'Complete email verification to enable all features.'
                
                logger.info(f"User registration and email sent successfully: {username}, role: {role}")
                
            except Exception as email_error:
                logger.error(f"Failed to send verification email: {str(email_error)}")
                result['message'] = 'Account created successfully, but verification email failed to send. Please contact support.'
                result['email_sent'] = False
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"SIGNUP ERROR: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Email verification endpoint"""
    try:
        result, status_code = AuthService.verify_email_token(token)
        
        if status_code == 200:
            logger.info(f"Email verification successful for token: {token[:10]}...")
            # Return an HTML page or redirect to frontend
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verified</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                    .success {{ color: green; }}
                    .container {{ max-width: 500px; margin: 0 auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="success">✓ Email Verified Successfully!</h1>
                    <p>Your account has been verified. You can now log in to your account.</p>
                    <p><a href="{request.host_url}">Return to Login</a></p>
                </div>
            </body>
            </html>
            """, 200
        else:
            logger.warning(f"Email verification failed for token: {token[:10]}...")
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Verification Failed</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                    .error {{ color: red; }}
                    .container {{ max-width: 500px; margin: 0 auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">✗ Verification Failed</h1>
                    <p>{result.get('error', 'Invalid or expired verification link.')}</p>
                    <p><a href="{request.host_url}">Return to Login</a></p>
                </div>
            </body>
            </html>
            """, status_code
            
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}", exc_info=True)
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verification Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .error {{ color: red; }}
                .container {{ max-width: 500px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="error">✗ Verification Error</h1>
                <p>An error occurred during verification. Please try again or contact support.</p>
                <p><a href="{request.host_url}">Return to Login</a></p>
            </div>
        </body>
        </html>
        """, 500


@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email'):
            response, status_code = create_error_response('Email is required', 400)
            return jsonify(response), status_code
        
        email = data.get('email')
        
        result, status_code = AuthService.resend_verification_email(email)
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Resend verification error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code


@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        if not data:
            response, status_code = create_error_response('No data provided', 400)
            return jsonify(response), status_code
        
        email = data.get('email')
        password = data.get('password')
        
        # Validate required fields
        if not email or not email.strip():
            response, status_code = create_error_response('Email is required', 400)
            return jsonify(response), status_code
        if not password:
            response, status_code = create_error_response('Password is required', 400)
            return jsonify(response), status_code
        
        logger.info(f"Login attempt for email: {email}")
        
        result, status_code = AuthService.authenticate_user(email, password)
        
        if status_code == 200:
            logger.info(f"Successful login for email: {email}")
        else:
            logger.warning(f"Failed login attempt for email: {email}")
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile endpoint"""
    try:
        user_id = get_jwt_identity()
        
        if not user_id:
            response, status_code = create_error_response('Invalid token', 401)
            return jsonify(response), status_code
        
        logger.info(f"Profile request for user_id: {user_id}")
        
        result, status_code = AuthService.get_user_profile(user_id)
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Profile error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code


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


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout endpoint"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Logout for user: {user_id}")
        
        return jsonify({'message': 'Successfully logged out'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Logout failed', 500)
        return jsonify(response), status_code


# Error handlers for the blueprint
@auth_bp.errorhandler(400)
def bad_request(error):
    response, status_code = create_error_response('Bad request', 400)
    return jsonify(response), status_code

@auth_bp.errorhandler(401)
def unauthorized(error):
    response, status_code = create_error_response('Unauthorized', 401)
    return jsonify(response), status_code

@auth_bp.errorhandler(403)
def forbidden(error):
    response, status_code = create_error_response('Forbidden', 403)
    return jsonify(response), status_code

@auth_bp.errorhandler(404)
def not_found(error):
    response, status_code = create_error_response('Endpoint not found', 404)
    return jsonify(response), status_code

@auth_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    response, status_code = create_error_response('Internal server error', 500)
    return jsonify(response), status_code