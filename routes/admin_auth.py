
from flask import Blueprint, request, jsonify
from middleware.auth import authenticate_admin
from services.auth_service import AuthService

admin_auth_bp = Blueprint('admin', __name__)

@admin_auth_bp.route('/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Request body is required'
            }), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({
                'success': False,
                'message': 'Email and password are requiredpip freeze > requirements.txt'
            }), 400
        
        # Validate credentials
        if not AuthService.validate_credentials(email, password):
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            }), 401
        
        # Generate token
        token = AuthService.generate_token(email)
        
        # Log login attempt
        AuthService.log_login(email, request.remote_addr)
        
        return jsonify({
            'success': True,
            'token': token,
            'admin': {
                'email': email,
                'role': 'admin',
                'permissions': ['read', 'write', 'authorize']
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': 'Authentication failed',
            'error': str(e) if request.args.get('debug') else None
        }), 500

@admin_auth_bp.route('/verify', methods=['GET'])
@authenticate_admin
def verify_token():
    """Verify JWT token endpoint"""
    return jsonify({
        'success': True,
        'valid': True,
        'admin': request.admin
    })

@admin_auth_bp.route('/logout', methods=['POST'])
@authenticate_admin
def admin_logout():
    """Admin logout endpoint"""
    try:
        # Log logout
        AuthService.log_logout(request.admin['email'], request.remote_addr)
        
        return jsonify({
            'success': True, 
            'message': 'Logged out successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': 'Logout failed'
        }), 500
