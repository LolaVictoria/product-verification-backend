import jwt
from functools import wraps
from flask import request, jsonify, current_app

def authenticate_admin(f):
    """Middleware to authenticate admin users"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Access denied. No token provided.'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            decoded = jwt.decode(
                token, 
                current_app.config['SECRET_KEY'], 
                algorithms=['HS256']
            )
            request.admin = decoded
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token.'}), 401
        
        return f(*args, **kwargs)
    return decorated

def authorize_admin(f):
    """Middleware to authorize admin actions"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'admin') or 'write' not in request.admin.get('permissions', []):
            return jsonify({'message': 'Access denied. Insufficient permissions.'}), 403
        return f(*args, **kwargs)
    return decorated
