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
            return create_error_response('No data provided')
        user_name = data.get('user_name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        wallet_address = data.get('wallet_address')
        
        # Register user
        result, status_code = AuthService.register_user(user_name, email, password, role, wallet_address)
        
        if status_code == 201 and role == 'manufacturer' and wallet_address:
            # Try to authorize on blockchain
            from app import blockchain_service
            auth_result = blockchain_service.authorize_manufacturer(wallet_address)
            
            if not auth_result['success']:
                logger.warning(f"Blockchain authorization failed for {wallet_address}: {auth_result.get('error')}")
                result['warning'] = 'User created but blockchain authorization failed. Contact support.'
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return create_error_response('Internal server error', 500)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        if not data:
            return create_error_response('No data provided')
        
        email = data.get('email')
        password = data.get('password')
        
        result, status_code = AuthService.authenticate_user(email, password)
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return create_error_response('Internal server error', 500)

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile endpoint"""
    try:
        user_id = get_jwt_identity()
        result, status_code = AuthService.get_user_profile(user_id)
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return create_error_response('Internal server error', 500)

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required()
def refresh_token():
    """Refresh JWT token endpoint"""
    try:
        from flask_jwt_extended import create_access_token, get_jwt
        
        current_user = get_jwt_identity()
        claims = get_jwt()
        
        new_token = create_access_token(
            identity=current_user,
            additional_claims={
                'role': claims.get('role'),
                'user_id': claims.get('user_id')
            }
        )
        
        return jsonify({'access_token': new_token}), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return create_error_response('Token refresh failed', 500)