import jwt
import os
import logging
from flask import request
from datetime import datetime, timedelta, timezone

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

logger = logging.getLogger(__name__)

class AuthError(Exception):
    """Custom authentication exception"""
    pass

def generate_token(user_data: dict, user_role: str) -> str:
    """
    Generate JWT token for user
    
    Args:
        user_data: Dictionary containing user_id and email
        user_role: Role of the user (admin, customer, manufacturer)
    
    Returns:
        JWT token string
    """
    try:
        if not JWT_SECRET_KEY:
            raise Exception("JWT_SECRET_KEY not configured")
        
        # Extract user_id from user_data
        user_id = user_data.get('user_id')
        if not user_id:
            raise Exception("user_id missing from user_data")
        
        payload = {
            'sub': str(user_id),
            'email': user_data.get('email'),
            'role': user_role,
            'exp': datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
            'iat': datetime.now(timezone.utc)
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        logger.info(f"Token generated for user {user_id} with role {user_role}")
        
        return token
        
    except Exception as e:
        logger.error(f"Error generating token: {e}")
        raise Exception("Token generation failed")

def verify_token(token):
    """Verify and decode JWT token"""
    try:
        if not JWT_SECRET_KEY:
            raise AuthError("JWT_SECRET_KEY not configured")
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
        
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        raise AuthError("Invalid token")

def get_token_from_request():
    """Extract token from request headers"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        raise AuthError("No authorization header")
    
    try:
        # Expect format: "Bearer <token>"
        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0] != 'Bearer':
            raise AuthError("Invalid authorization header format")
        
        token = parts[1]
        return token
        
    except IndexError:
        raise AuthError("Invalid authorization header format")