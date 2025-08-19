from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services import AuthService, BlockchainService
from utils.helpers import create_error_response, create_success_response
import logging

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
        
        # Create user account (no blockchain interaction yet)
        result, status_code = AuthService.register_user(username, email, password, role, wallet_address)
        
        if status_code == 201:
            if role.lower() == 'manufacturer':
                result['blockchain_status'] = 'pending_verification'
                result['message'] = 'Account created successfully. Blockchain verification will be completed within 24 hours.'
                result['note'] = 'You can start using the platform immediately. Product registration will be enabled after blockchain verification.'
            else:
                result['message'] = 'Developer account created successfully.'
        
        logger.info(f"User registration successful: {username}, role: {role}")
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"SIGNUP ERROR: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code

# ADMIN ENDPOINT - For batch authorization (you run this periodically)
@auth_bp.route('/admin/batch-authorize-manufacturers', methods=['POST'])
@jwt_required()
def batch_authorize_manufacturers():
    """Admin endpoint to authorize multiple manufacturers at once (saves gas)"""
    try:
        user_id = get_jwt_identity()
        
        # Check if user is admin (implement this check in your AuthService)
        user_profile, _ = AuthService.get_user_profile(user_id)
        if not user_profile.get('user', {}).get('is_admin', False):
            response, status_code = create_error_response('Admin access required', 403)
            return jsonify(response), status_code
        
        # Get all pending manufacturers from database
        pending_manufacturers = AuthService.get_pending_manufacturers()  # You need to implement this
        
        if not pending_manufacturers:
            return jsonify({'message': 'No pending manufacturers to authorize'}), 200
        
        # Batch authorize on blockchain
        from app import blockchain_service
        wallet_addresses = [m['wallet_address'] for m in pending_manufacturers]
        
        try:
            # Use batch authorization (you'll need to implement this in your smart contract)
            auth_result = blockchain_service.batch_authorize_manufacturers(wallet_addresses)
            
            if auth_result.get('success'):
                # Update database status for all authorized manufacturers
                AuthService.update_manufacturers_blockchain_status(wallet_addresses, 'verified')
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully authorized {len(wallet_addresses)} manufacturers',
                    'tx_hash': auth_result.get('tx_hash'),
                    'authorized_addresses': wallet_addresses
                }), 200
            else:
                return jsonify(create_error_response(
                    f"Batch authorization failed: {auth_result.get('error')}", 400
                )[0]), 400
                
        except Exception as blockchain_error:
            logger.error(f"Batch authorization error: {blockchain_error}")
            return jsonify(create_error_response(
                'Blockchain authorization service error', 500
            )[0]), 500
            
    except Exception as e:
        logger.error(f"Batch authorization error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Internal server error', 500)
        return jsonify(response), status_code

# MANUFACTURER ENDPOINT - Check their authorization status
@auth_bp.route('/manufacturer/status', methods=['GET'])
@jwt_required()
def get_manufacturer_status():
    """Get manufacturer's blockchain authorization status"""
    try:
        user_id = get_jwt_identity()
        
        # Get user profile
        profile_result, profile_status = AuthService.get_user_profile(user_id)
        if profile_status != 200:
            return jsonify(create_error_response('Unable to get user profile', 400)[0]), 400
        
        user = profile_result.get('user', {})
        if user.get('role', '').lower() != 'manufacturer':
            return jsonify(create_error_response('Only manufacturers can check authorization status', 403)[0]), 403
        
        wallet_address = user.get('wallet_address')
        if not wallet_address:
            return jsonify(create_error_response('No wallet address found', 400)[0]), 400
        
        # Check blockchain authorization status
        from app import blockchain_service
        try:
            verification_result = blockchain_service.verify_manufacturer_authorization(wallet_address)
            
            return jsonify({
                'wallet_address': wallet_address,
                'blockchain_authorized': verification_result.get('authorized', False),
                'database_status': user.get('blockchain_status', 'pending'),
                'can_register_products': verification_result.get('authorized', False)
            }), 200
            
        except Exception as blockchain_error:
            logger.error(f"Status check error: {blockchain_error}")
            return jsonify({
                'wallet_address': wallet_address,
                'blockchain_authorized': False,
                'database_status': user.get('blockchain_status', 'pending'),
                'can_register_products': False,
                'error': 'Unable to check blockchain status'
            }), 200
            
    except Exception as e:
        logger.error(f"Status check error: {str(e)}", exc_info=True)
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