from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services import AuthService, BlockchainService
from utils.helpers import create_error_response, create_success_response
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)  # Fixed: __name__ was **name**

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    try:
        data = request.get_json()
        if not data:
            response, status_code = create_error_response('No data provided', 400)
            return jsonify(response), status_code
        
        # Get and validate required fields
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        wallet_address = data.get('wallet_address')
        
        # Validate required fields
        required_fields = {
            'username': username,
            'email': email,
            'password': password,
            'role': role
        }
        
        for field_name, field_value in required_fields.items():
            if not field_value or not str(field_value).strip():
                response, status_code = create_error_response(f'{field_name} is required', 400)
                return jsonify(response), status_code
        
        # Validate role
        if role.lower() not in ['developer', 'manufacturer']:
            response, status_code = create_error_response('Invalid role. Must be "developer" or "manufacturer"', 400)
            return jsonify(response), status_code
        
        # Log the signup attempt (without password)
        logger.info(f"Signup attempt for username: {username}, email: {email}, role: {role}")
        
        # Register user
        result, status_code = AuthService.register_user(username, email, password, role, wallet_address)
        
        # Handle blockchain authorization for manufacturers
        if status_code == 201 and role.lower() == 'manufacturer' and wallet_address:
            try:
                from app import blockchain_service
                auth_result = blockchain_service.authorize_manufacturer(wallet_address)
                if not auth_result['success']:
                    logger.warning(f"Blockchain authorization failed for {wallet_address}: {auth_result.get('error')}")
                    result['warning'] = 'User created but blockchain authorization failed. Contact support.'
            except Exception as blockchain_error:
                logger.error(f"Blockchain service error: {blockchain_error}")
                result['warning'] = 'User created but blockchain service unavailable.'
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}", exc_info=True)  # Added exc_info for stack trace
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
@jwt_required(refresh=True)  # Added refresh=True for refresh tokens
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
    """Logout endpoint (optional - for token blacklisting)"""
    try:
        # If you implement token blacklisting, add logic here
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