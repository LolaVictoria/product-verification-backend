import jwt
import os
import logging
from flask import request
from datetime import datetime, timedelta

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

logger = logging.getLogger(__name__)
class AuthError(Exception):
    """Custom authentication exception"""
    pass

       
def generate_token(self, user_id: str, user_role: str) -> str:
        """Generate JWT token for user"""
        try:
            payload = {
                'sub': str(user_id),
                'role': user_role,
                'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours),
                'iat': datetime.utcnow()
            }
            return jwt.encode(payload, self.secret_key, algorithm='HS256')
        except Exception as e:
            logger.error(f"Error generating token: {e}")
            raise Exception("Token generation failed")

def verify_token(token):
        """Verify and decode JWT token"""
        try:
            if token.startswith('Bearer '):
                token = token[7:]  
            
            
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthError("Invalid token")

def get_token_from_request():
        """Extract token from request headers"""
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            raise AuthError("No authorization header")
        
        try:
            # Expect format: "Bearer <token>"
            token = auth_header.split(' ')[1]
            return token
        except IndexError:
            raise AuthError("Invalid authorization header format")

