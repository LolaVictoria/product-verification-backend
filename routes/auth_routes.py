# routes/auth_routes.py
from flask import Blueprint, request, make_response, current_app
from functools import wraps
from datetime import datetime, timezone, timedelta
import jwt
import os
from bson import ObjectId
from services.__init__ import auth_service, ProfileUpdateHandler
from utils.validators import validate_user_registration, validate_login_data
from utils.formatters import format_user_response
from middleware.rate_limiting import rate_limit
from middleware.auth_middleware import auth_middleware
from utils.helper_functions import get_db_connection, blacklist_token, get_user_by_id, format_user_profile

auth_bp = Blueprint('auth', __name__)

# Add this debug version to your login route temporarily

# Updated login route
@auth_bp.route('/login', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def login():
    print("=== LOGIN ENDPOINT HIT ===") 
    try:
        data = request.get_json()
        print(f"Received data: {data}")
        # Validate input data
        validation_error = validate_login_data(data)
        print(f"Validation error: {validation_error}")
        if validation_error:
            return auth_middleware.create_error_response(validation_error, 400)
        
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
            return auth_middleware.create_error_response(result['message'], 401)
        
        # Format the user response
        formatted_user = format_user_response(result['user'])
        
        # DEBUG: Print formatted user
        print("=== FORMATTED USER ===")
        print(f"Formatted: {formatted_user}")
        print("=====================")
        
        response_data = {
            'token': result['token'],
            'user': formatted_user,
            'refresh_token': result.get('refresh_token'),  # Add if available
            'expires_at': result['expires_at']
        }
        
        # DEBUG: Print final response
        print("=== FINAL RESPONSE ===")
        print(f"Response: {response_data}")
        print("====================")
        
        return auth_middleware.create_success_response(response_data, "Login successful", 200)
        
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return auth_middleware.create_error_response("Authentication failed", 500)
    
@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint - blacklist token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Blacklist the token
        blacklist_result = blacklist_token(token)
        if not blacklist_result:
            return auth_middleware.create_error_response("Token blacklisting failed", 500)
        
        return auth_middleware.create_success_response({}, "Logged out successfully")
        
    except Exception as e:
        print(f"Logout error: {e}")
        return auth_middleware.create_error_response("Logout failed", 500)

@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh authentication token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Refresh token
        result = auth_service.refresh_token(token)
        
        if not result['success']:
            return auth_middleware.create_error_response(result['message'], 401)
        
        return auth_middleware.create_success_response({
            'token': result['token'],
            'expires_at': result['expires_at']
        }, "Token refreshed successfully")
        
    except Exception as e:
        print(f"Token refresh error: {e}")
        return auth_middleware.create_error_response("Token refresh failed", 500)

@auth_bp.route('/verify-token', methods=['GET'])
def verify_token():
    """Verify if current token is valid"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("No token provided", 400)
        
        token = auth_header.split(' ')[1]
        
        # Verify token
        result = auth_service.verify_token(token)
        
        if not result['valid']:
            return auth_middleware.create_error_response(result['message'], 401)
        
        return auth_middleware.create_success_response({
            'valid': True,
            'user': format_user_response(result['user']),
            'expires_at': result['expires_at']
        }, "Token is valid")
        
    except Exception as e:
        print(f"Token verification error: {e}")
        return auth_middleware.create_error_response("Token verification failed", 500)

@auth_bp.route('/change-password', methods=['PUT'])
def change_password():
    """Change user password"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        # Validate input
        if not data.get('current_password') or not data.get('new_password'):
            return auth_middleware.create_error_response("Current and new passwords required", 400)
        
        # Change password
        result = auth_service.change_password(
            token,
            data['current_password'],
            data['new_password']
        )
        
        if not result['success']:
            return auth_middleware.create_error_response(result['message'], 400)
        
        return auth_middleware.create_success_response({}, "Password changed successfully")
        
    except Exception as e:
        print(f"Password change error: {e}")
        return auth_middleware.create_error_response("Password change failed", 500)

@auth_bp.route('/forgot-password', methods=['POST'])
@rate_limit({'per_minute': 3, 'per_hour': 10})
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return auth_middleware.create_error_response("Email is required", 400)
        
        # Initiate password reset
        result = auth_service.initiate_password_reset(email)
        
        # Always return success for security (don't reveal if email exists)
        return auth_middleware.create_success_response({}, 
            "If the email exists, you will receive password reset instructions")
        
    except Exception as e:
        print(f"Password reset initiation error: {e}")
        return auth_middleware.create_error_response("Password reset request failed", 500)

@auth_bp.route('/reset-password', methods=['POST'])
@rate_limit({'per_minute': 5, 'per_hour': 20})
def reset_password():
    """Reset password using token"""
    try:
        data = request.get_json()
        
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        
        if not reset_token or not new_password:
            return auth_middleware.create_error_response("Reset token and new password required", 400)
        
        # Reset password
        result = auth_service.reset_password(reset_token, new_password)
        
        if not result['success']:
            return auth_middleware.create_error_response(result['message'], 400)
        
        return auth_middleware.create_success_response({}, "Password reset successfully")
        
    except Exception as e:
        print(f"Password reset error: {e}")
        return auth_middleware.create_error_response("Password reset failed", 500)

@auth_bp.route('/validate-reset-token', methods=['GET'])
def validate_reset_token():
    """Validate password reset token"""
    try:
        reset_token = request.args.get('token')
        
        if not reset_token:
            return auth_middleware.create_error_response("Reset token is required", 400)
        
        # Validate token
        result = auth_service.validate_reset_token(reset_token)
        
        if not result['valid']:
            return auth_middleware.create_error_response(result['message'], 400)
        
        return auth_middleware.create_success_response({
            'valid': True,
            'email': result['email']
        }, "Reset token is valid")
        
    except Exception as e:
        print(f"Reset token validation error: {e}")
        return auth_middleware.create_error_response("Token validation failed", 500)

# Manufacturer-specific authentication
@auth_bp.route('/manufacturer/verify-wallet', methods=['POST'])
@rate_limit({'per_minute': 10, 'per_hour': 50})
def verify_manufacturer_wallet():
    """Verify manufacturer wallet address"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        wallet_address = data.get('wallet_address')
        signature = data.get('signature')
        message = data.get('message')
        
        if not all([wallet_address, signature, message]):
            return auth_middleware.create_error_response("Wallet address, signature, and message required", 400)
        
        # Verify wallet
        result = auth_service.verify_manufacturer_wallet(
            token, wallet_address, signature, message
        )
        
        if not result['success']:
            return auth_middleware.create_error_response(result['message'], 400)
        
        return auth_middleware.create_success_response({
            'wallet_verified': True,
            'user': format_user_response(result['user'])
        }, "Wallet verified successfully")
        
    except Exception as e:
        print(f"Wallet verification error: {e}")
        return auth_middleware.create_error_response("Wallet verification failed", 500)

@auth_bp.route('/manufacturer/request-verification', methods=['POST'])
@rate_limit({'per_minute': 2, 'per_hour': 10})
def request_manufacturer_verification():
    """Request manufacturer account verification"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return auth_middleware.create_error_response("Authentication required", 401)
        
        token = auth_header.split(' ')[1]
        data = request.get_json()
        
        # Request verification
        result = auth_service.request_manufacturer_verification(token, data)
        
        if not result['success']:
            return auth_middleware.create_error_response(result['message'], 400)
        
        return auth_middleware.create_success_response({
            'verification_request_id': result['request_id']
        }, "Verification request submitted successfully")
        
    except Exception as e:
        print(f"Verification request error: {e}")
        return auth_middleware.create_error_response("Verification request failed", 500)
    

# ===============================
# PROFILE
# ===============================

@auth_bp.route('/manufacturer/profile', methods=['GET', 'OPTIONS'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def get_manufacturer_profile(current_user_id, current_user_role):
    """Get manufacturer profile details"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return auth_middleware.add_cors_headers(response)
    
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return auth_middleware.create_cors_response({"error": "User not found"}, 404)
        
        profile_data = format_user_profile(user)
        return auth_middleware.create_cors_response({
            "status": "success",
            "user": profile_data
        }, 200)
        
    except Exception as e:
        print(f"Manufacturer profile error: {e}")
        return auth_middleware.create_cors_response({"error": "Internal server error"}, 500)


@auth_bp.route('/customer/profile', methods=['GET', 'OPTIONS'])
@auth_middleware.token_required_with_roles(allowed_roles=['customer'])
def get_customer_profile(current_user_id, current_user_role):
    """Get customer profile details"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        return auth_middleware.add_cors_headers(response)
    
    try:
        user = get_user_by_id(current_user_id)
        if not user:
            return auth_middleware.create_cors_response({"error": "User not found"}, 404)
        
        profile_data = format_user_profile(user)
        
        return auth_middleware.create_cors_response({
            "status": "success",
            "user": profile_data
        }, 200)
        
    except Exception as e:
        print(f"Customer profile error: {e}")
        return auth_middleware.create_cors_response({"error": "Internal server error"}, 500)

@auth_bp.route('/manufacturer/profile/quick-update', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def quick_profile_update(current_user_id, current_user_role):
    """
    Simple endpoint for single field updates from frontend
    
    Request format:
    {
        "field": "primary_email",
        "value": "new@example.com"
    }
    """
    try:
        data = request.get_json()
        field = data.get('field')
        value = data.get('value')
        
        if not field or value is None:
            return auth_middleware.create_cors_response({"error": "Field and value are required"}, 400)
        
        # Map simple fields to unified format
        field_mappings = {
            'primary_email': lambda v: {"direct_updates": {"primary_email": v}},
            'primary_wallet': lambda v: {"direct_updates": {"primary_wallet": v}},
            'company_name': lambda v: {"company_name": v}
        }
        
        if field not in field_mappings:
            return auth_middleware.create_cors_response({"error": f"Field '{field}' not supported for quick updates"}, 400)
        
        # Transform and forward to unified endpoint
        unified_data = field_mappings[field](value)
        request.json = unified_data
        
        return update_manufacturer_profile(current_user_id, current_user_role)
        
    except Exception as e:
        print(f"Quick update error: {e}")
        return auth_middleware.create_cors_response({"error": "Internal server error"}, 500)


@auth_bp.route('/manufacturer/profile-update', methods=['PUT', 'PATCH'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def update_manufacturer_profile(current_user_id, current_user_role):
    """
    Unified endpoint for updating manufacturer profile.
    
    Supports batch operations and single field updates.
    
    Request body format:
    {
        "email_operations": [
            {"operation": "add", "email": "new@example.com"},
            {"operation": "set_primary", "email": "primary@example.com"},
            {"operation": "remove", "email": "old@example.com"}
        ],
        "wallet_operations": [
            {"operation": "add", "wallet_address": "0x123..."},
            {"operation": "set_primary", "wallet_address": "0x456..."}
        ],
        "company_name": "New Company Name",
        "direct_updates": {
            "primary_email": "direct@example.com",
            "primary_wallet": "0x789..."
        }
    }
    """
    try:
        data = request.get_json()
        if not data:
            return auth_middleware.create_cors_response({"error": "Request body is required"}, 400)
        
        # Get current user
        user = get_user_by_id(current_user_id)
        if not user:
            return auth_middleware.create_cors_response({"error": "User not found"}, 404)
        
        # Prepare update data
        final_updates = {}
        operations_performed = []
        
        # Handle email operations
        if 'email_operations' in data and data['email_operations']:
            try:
                email_updates = ProfileUpdateHandler.handle_email_operations(
                    data['email_operations'], user, current_user_id
                )
                final_updates.update(email_updates)
                operations_performed.append(f"Processed {len(data['email_operations'])} email operation(s)")
            except ValueError as e:
                return auth_middleware.create_cors_response({"error": str(e)}, 400)
        
        # Handle wallet operations
        if 'wallet_operations' in data and data['wallet_operations']:
            try:
                wallet_updates = ProfileUpdateHandler.handle_wallet_operations(
                    data['wallet_operations'], user, current_user_id
                )
                final_updates.update(wallet_updates)
                operations_performed.append(f"Processed {len(data['wallet_operations'])} wallet operation(s)")
            except ValueError as e:
                return auth_middleware.create_cors_response({"error": str(e)}, 400)
        
        # Handle company name update
        if 'company_name' in data and data['company_name']:
            try:
                company_updates = ProfileUpdateHandler.handle_company_update(
                    data['company_name'], user
                )
                final_updates.update(company_updates)
                operations_performed.append("Updated company name")
            except ValueError as e:
                return auth_middleware.create_cors_response({"error": str(e)}, 400)
        
        # Handle direct field updates (backwards compatibility)
        if 'direct_updates' in data:
            direct = data['direct_updates']
            
            # Direct email update
            if 'primary_email' in direct:
                email = direct['primary_email'].strip().lower()
                current_emails = final_updates.get('emails', user.get('emails', []))
                if email not in current_emails:
                    return auth_middleware.create_cors_response({"error": "Email not found in your account"}, 400)
                final_updates['primary_email'] = email
                operations_performed.append("Set primary email")
            
            # Direct wallet update
            if 'primary_wallet' in direct:
                wallet = direct['primary_wallet'].strip()
                current_wallets = final_updates.get('wallet_addresses', user.get('wallet_addresses', []))
                verified_wallets = user.get('verified_wallets', [])
                
                if wallet not in current_wallets:
                    return auth_middleware.create_cors_response({"error": "Wallet not found in your account"}, 400)
                if wallet not in verified_wallets:
                    return auth_middleware.create_cors_response({"error": "Wallet must be verified before setting as primary"}, 400)
                
                final_updates['primary_wallet'] = wallet
                operations_performed.append("Set primary wallet")
            
            # Support for legacy single field updates
            for field in ['emails', 'wallet_addresses', 'company_names', 'current_company_name']:
                if field in direct:
                    final_updates[field] = direct[field]
                    operations_performed.append(f"Updated {field}")
        
        # Check if any updates were provided
        if not final_updates:
            return auth_middleware.create_cors_response({"error": "No valid updates provided"}, 400)
        
        # Apply updates to database
        final_updates['updated_at'] = datetime.now(timezone.utc)
        
        db = get_db_connection()
        result = db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$set": final_updates}
        )
        
        if result.matched_count == 0:
            return auth_middleware.create_cors_response({"error": "User not found"}, 404)
        
        # Get updated user data
        updated_user = get_user_by_id(current_user_id)
        profile_data = format_user_profile(updated_user)
        
        return auth_middleware.create_cors_response({
            "status": "success",
            "message": f"Profile updated successfully. {'; '.join(operations_performed)}",
            "user": profile_data,
            "operations_performed": operations_performed
        }, 200)
        
    except Exception as e:
        print(f"Profile update error: {e}")
        return auth_middleware.create_cors_response({
            "error": "Internal server error",
            "details": str(e) if current_app.debug else None
        }, 500)

# Keep individual endpoints for backwards compatibility (optional)
@auth_bp.route('/manufacturer/profile/add-email', methods=['POST'])
@auth_middleware.token_required_with_roles(allowed_roles=['manufacturer'])
def add_email_legacy(current_user_id, current_user_role):
    """Legacy endpoint - redirects to unified endpoint"""
    data = request.get_json()
    email = data.get('email')
    
    # Transform to new format
    unified_data = {
        "email_operations": [{"operation": "add", "email": email}]
    }
    
    # Create new request and forward
    request.json = unified_data
    return update_manufacturer_profile(current_user_id, current_user_role)


#
################################################
#E. O. D
#################################