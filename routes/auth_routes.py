# routes/auth_routes.py
from flask import Blueprint, request, jsonify, g
from functools import wraps
from datetime import datetime, timezone, timedelta
import jwt
import os
from bson import ObjectId

from services.auth_service import AuthService
from utils.validators import validate_user_registration, validate_login_data
from utils.formatters import format_user_response, create_success_response, create_error_response
from middleware.rate_limiting import rate_limit
from utils.helper_functions import get_db_connection, blacklist_token

# Create blueprint
auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

# Add this debug version to your login route temporarily

@auth_bp.route('/login', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        # Validate input data
        validation_error = validate_login_data(data)
        if validation_error:
            return create_error_response(validation_error, 400)
        
        # Attempt login
        result = auth_service.authenticate_user(
            data.get('email'),
            data.get('password')
        )
        
        # DEBUG: Print what auth_service returns
        print("=== AUTH SERVICE RESULT ===")
        print(f"Success: {result.get('success')}")
        print(f"User data: {result.get('user')}")
        print(f"User ID: {result.get('user', {}).get('_id')}")
        print("========================")
        
        if not result['success']:
            return create_error_response(result['message'], 401)
        
        # Format the user response
        formatted_user = format_user_response(result['user'])
        
        # DEBUG: Print formatted user
        print("=== FORMATTED USER ===")
        print(f"Formatted: {formatted_user}")
        print("=====================")
        
        response_data = {
            'token': result['token'],
            'user': formatted_user,
            'expires_at': result['expires_at']
        }
        
        # DEBUG: Print final response
        print("=== FINAL RESPONSE ===")
        print(f"Response: {response_data}")
        print("====================")
        
        return create_success_response(response_data, "Login successful")
        
    except Exception as e:
        print(f"Login error: {e}")
        return create_error_response("Authentication failed", 500)
    
@auth_bp.route('/signup', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate registration data
        validation_error = validate_user_registration(data)
        if validation_error:
            return create_error_response(validation_error, 400)
        
        # Register user
        result = auth_service.register_user(data)
        
        if not result['success']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({
            'user_id': result['user_id'],
            'user': format_user_response(result['user']) if result.get('user') else None
        }, "User registered successfully", 201)
        
    except Exception as e:
        print(f"Registration error: {e}")
        return create_error_response("Registration failed", 500)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint - blacklist token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Blacklist the token
        blacklist_result = blacklist_token(token)
        if not blacklist_result:
            return create_error_response("Token blacklisting failed", 500)
        
        return create_success_response({}, "Logged out successfully")
        
    except Exception as e:
        print(f"Logout error: {e}")
        return create_error_response("Logout failed", 500)

@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh authentication token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Refresh token
        result = auth_service.refresh_token(token)
        
        if not result['success']:
            return create_error_response(result['message'], 401)
        
        return create_success_response({
            'token': result['token'],
            'expires_at': result['expires_at']
        }, "Token refreshed successfully")
        
    except Exception as e:
        print(f"Token refresh error: {e}")
        return create_error_response("Token refresh failed", 500)

@auth_bp.route('/verify-token', methods=['GET'])
def verify_token():
    """Verify if current token is valid"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        result = auth_service.verify_token(token)
        
        if not result['valid']:
            return create_error_response(result['message'], 401)
        
        return create_success_response({
            'valid': True,
            'user': format_user_response(result['user']),
            'expires_at': result['expires_at']
        }, "Token is valid")
        
    except Exception as e:
        print(f"Token verification error: {e}")
        return create_error_response("Token verification failed", 500)

@auth_bp.route('/change-password', methods=['PUT'])
def change_password():
    """Change user password"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        # Validate input
        if not data.get('current_password') or not data.get('new_password'):
            return create_error_response("Current and new passwords required", 400)
        
        # Change password
        result = auth_service.change_password(
            token,
            data['current_password'],
            data['new_password']
        )
        
        if not result['success']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({}, "Password changed successfully")
        
    except Exception as e:
        print(f"Password change error: {e}")
        return create_error_response("Password change failed", 500)

@auth_bp.route('/forgot-password', methods=['POST'])
@rate_limit({'per_minute': 3, 'per_hour': 10})
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return create_error_response("Email is required", 400)
        
        # Initiate password reset
        result = auth_service.initiate_password_reset(email)
        
        # Always return success for security (don't reveal if email exists)
        return create_success_response({}, 
            "If the email exists, you will receive password reset instructions")
        
    except Exception as e:
        print(f"Password reset initiation error: {e}")
        return create_error_response("Password reset request failed", 500)

@auth_bp.route('/reset-password', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def reset_password():
    """Reset password using token"""
    try:
        data = request.get_json()
        
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        
        if not reset_token or not new_password:
            return create_error_response("Reset token and new password required", 400)
        
        # Reset password
        result = auth_service.reset_password(reset_token, new_password)
        
        if not result['success']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({}, "Password reset successfully")
        
    except Exception as e:
        print(f"Password reset error: {e}")
        return create_error_response("Password reset failed", 500)

@auth_bp.route('/validate-reset-token', methods=['GET'])
def validate_reset_token():
    """Validate password reset token"""
    try:
        reset_token = request.args.get('token')
        
        if not reset_token:
            return create_error_response("Reset token is required", 400)
        
        # Validate token
        result = auth_service.validate_reset_token(reset_token)
        
        if not result['valid']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({
            'valid': True,
            'email': result['email']
        }, "Reset token is valid")
        
    except Exception as e:
        print(f"Reset token validation error: {e}")
        return create_error_response("Token validation failed", 500)

# Manufacturer-specific authentication
@auth_bp.route('/manufacturer/verify-wallet', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def verify_manufacturer_wallet():
    """Verify manufacturer wallet address"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        wallet_address = data.get('wallet_address')
        signature = data.get('signature')
        message = data.get('message')
        
        if not all([wallet_address, signature, message]):
            return create_error_response("Wallet address, signature, and message required", 400)
        
        # Verify wallet
        result = auth_service.verify_manufacturer_wallet(
            token, wallet_address, signature, message
        )
        
        if not result['success']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({
            'wallet_verified': True,
            'user': format_user_response(result['user'])
        }, "Wallet verified successfully")
        
    except Exception as e:
        print(f"Wallet verification error: {e}")
        return create_error_response("Wallet verification failed", 500)

@auth_bp.route('/manufacturer/request-verification', methods=['POST'])
@rate_limit({'per_minute': 2, 'per_hour': 10})
def request_manufacturer_verification():
    """Request manufacturer account verification"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        # Request verification
        result = auth_service.request_manufacturer_verification(token, data)
        
        if not result['success']:
            return create_error_response(result['message'], 400)
        
        return create_success_response({
            'verification_request_id': result['request_id']
        }, "Verification request submitted successfully")
        
    except Exception as e:
        print(f"Verification request error: {e}")
        return create_error_response("Verification request failed", 500)