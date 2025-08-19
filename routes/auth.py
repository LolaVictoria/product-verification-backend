from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services import AuthService, BlockchainService
from utils.helpers import create_error_response, create_success_response
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    
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
        wallet_address = data.get('wallet_address')
        
        # Validate required fields
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
        
        # FOR MANUFACTURERS: Perform blockchain authorization BEFORE creating account
        if role.lower() == 'manufacturer' and wallet_address:
            try:
                logger.info(f"Attempting blockchain authorization for manufacturer: {wallet_address}")
                from app import blockchain_service
                
                # Check if blockchain service is available
                if not blockchain_service or not blockchain_service.is_connected():
                    logger.error("Blockchain service is not available or not connected")
                    response, status_code = create_error_response(
                        'Blockchain service is currently unavailable. Please try again later.', 503
                    )
                    return jsonify(response), status_code
                
                # Attempt to authorize manufacturer on blockchain
                auth_result = blockchain_service.authorize_manufacturer(wallet_address)
                logger.info(f"Blockchain auth result: {auth_result}")
                
                if not auth_result.get('success', False):
                    error_msg = auth_result.get('error', 'Unknown blockchain error')
                    logger.error(f"Blockchain authorization failed for {wallet_address}: {error_msg}")
                    response, status_code = create_error_response(
                        f'Manufacturer authorization failed: {error_msg}', 400
                    )
                    return jsonify(response), status_code
                
                logger.info(f"Blockchain authorization successful for {wallet_address}")
                
            except Exception as blockchain_error:
                logger.error(f"Blockchain service error during authorization: {blockchain_error}", exc_info=True)
                response, status_code = create_error_response(
                    'Blockchain authorization failed due to service error. Please try again later.', 503
                )
                return jsonify(response), status_code
        
        logger.info("All validations passed (including blockchain for manufacturers), calling AuthService.register_user")
        
        # NOW register user (only after blockchain auth succeeds for manufacturers)
        result, status_code = AuthService.register_user(username, email, password, role, wallet_address)
        
        logger.info(f"AuthService.register_user returned: result={result}, status_code={status_code}")
        
        # If manufacturer registration was successful, add blockchain confirmation to response
        if status_code == 201 and role.lower() == 'manufacturer':
            result['blockchain_authorized'] = True
            result['message'] = 'Account created successfully with blockchain authorization'
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"SIGNUP ERROR: {str(e)}", exc_info=True)
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

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout endpoint (optional - for token blacklisting)"""
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