# services/token_service.py
import jwt
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import logging
import hashlib

logger = logging.getLogger(__name__)
class TokenService:
    """Service for handling authentication operations"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
    
    
    
    def refresh_token(self, old_token: str) -> Dict[str, Any]:
        """Refresh user token"""
        try:
            # Decode old token to get user info
            payload = jwt.decode(old_token, self.secret_key, algorithms=['HS256'])
            user_id = payload.get('sub')
            user_role = payload.get('role')
            
            if not user_id or not user_role:
                return {
                    'success': False,
                    'error': 'Invalid token payload'
                }
            
            # Generate new token
            from app.services.auth.auth_service import AuthService
            auth_service = AuthService()
            new_token = auth_service.generate_token(user_id, user_role)
            
            # Blacklist old token
            self.blacklist_token(old_token)
            
            return {
                'success': True,
                'token': new_token,
                'expires_at': (datetime.utcnow() + timedelta(hours=self.token_expiry_hours)).isoformat()
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'success': False,
                'error': 'Token has expired'
            }
        except jwt.InvalidTokenError:
            return {
                'success': False,
                'error': 'Invalid token'
            }
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return {
                'success': False,
                'error': 'Token refresh failed'
            }
    def logout_user(self, token: str) -> dict:
        """Logout user by blacklisting token"""
        try:
            if TokenService.blacklist_token(token):
                return {
                    'success': True,
                    'message': 'Logged out successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Token blacklisting failed'
                }
        except Exception as e:
            return {
                'success': False,
                'message': 'Logout failed'
            }
    
    def blacklist_token(self, token: str) -> Dict[str, Any]:
        """Add JWT token to blacklist (for logout/token invalidation)"""
        try:
            if not token:
                return {
                    'success': False,
                    'error': 'Token is required'
                }
            
            # Decode token to get expiration
            try:
                payload = jwt.decode(token, self.secret_key, algorithms=['HS256'], options={'verify_exp': False})
                user_id = payload.get('sub')
                exp = payload.get('exp')
            except jwt.InvalidTokenError:
                return {
                    'success': False,
                    'error': 'Invalid token format'
                }
            
            # Store in blacklist with expiration
            blacklist_doc = {
                'token_hash': hashlib.sha256(token.encode()).hexdigest()[:32],  # Store hash, not full token
                'user_id': user_id,
                'blacklisted_at': datetime.utcnow(),
                'expires_at': datetime.utcfromtimestamp(exp) if exp else datetime.utcnow() + timedelta(hours=24)
            }
            
            # Insert into database
            self.db.blacklisted_tokens.insert_one(blacklist_doc)
            
            # Clean up expired tokens (optional optimization)
            self._cleanup_expired_tokens()
            
            return {
                'success': True,
                'message': 'Token blacklisted successfully'
            }
            
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            return {
                'success': False,
                'error': 'Token blacklisting failed'
            }

    def _cleanup_expired_tokens(self):
        """Remove expired tokens from blacklist"""
        try:
            self.db.blacklisted_tokens.delete_many({
                'expires_at': {'$lt': datetime.utcnow()}
            })
        except Exception as e:
            logger.warning(f"Token cleanup failed: {e}")

    def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        try:
            if not token:
                return False
                
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:32]
            
            blacklisted = self.db.blacklisted_tokens.find_one({
                'token_hash': token_hash,
                'expires_at': {'$gt': datetime.utcnow()}
            })
            
            return blacklisted is not None
            
        except Exception as e:
            logger.error(f"Error checking token blacklist: {e}")
            return False  # Fail open for availability

        
    @staticmethod
    def generate_jwt_token(user_id: str, user_role: str, secret_key: str, expires_in_hours: int = 24) -> str:
        """Generate JWT token"""
        try:
            payload = {
                'sub': user_id,
                'role': user_role,
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            }
            
            return jwt.encode(payload, secret_key, algorithm='HS256')
            
        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise
    
    @staticmethod
    def verify_jwt_token(token: str, secret_key: str) -> Dict[str, Any]:
        """Verify JWT token and return payload"""
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return {'valid': True, 'payload': payload}
            
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token has expired'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'error': 'Token is invalid'}
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return {'valid': False, 'error': 'Token verification failed'}
 
token_service = TokenService()