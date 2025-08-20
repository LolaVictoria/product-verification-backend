# Create this as test_auth.py to verify your blueprint works
from flask import Blueprint, request, jsonify

# Create a minimal auth blueprint for testing
test_auth_bp = Blueprint('test_auth', __name__, url_prefix='/auth')

@test_auth_bp.route('/test', methods=['GET', 'POST', 'OPTIONS'])
def test_route():
    """Simple test route"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    
    return jsonify({
        'message': 'Test route working!',
        'method': request.method,
        'endpoint': '/auth/test'
    }), 200

@test_auth_bp.route('/signup', methods=['POST', 'OPTIONS'])
def test_signup():
    """Minimal signup test"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    
    data = request.get_json() or {}
    
    return jsonify({
        'message': 'Signup test route working!',
        'received_data': list(data.keys()) if data else [],
        'endpoint': '/auth/signup'
    }), 200

# Temporarily replace your auth import in routes/__init__.py with:
# from .test_auth import test_auth_bp as auth_bp