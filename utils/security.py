import bcrypt
import hashlib
import secrets
import jwt
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class SecurityUtils:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(stored_hash: str, provided_password: str) -> bool:
        """Verify password against stored hash"""
        try:
            # Check if it's bcrypt
            if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$') or stored_hash.startswith('$2y$'):
                return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash.encode('utf-8'))
            
            # Check if it's pbkdf2 (Werkzeug style)
            elif stored_hash.startswith('pbkdf2:'):
                from werkzeug.security import check_password_hash
                return check_password_hash(stored_hash, provided_password)
            
            # Fallback for plain text (not recommended)
            elif len(stored_hash) < 50:
                logger.warning("Plain text password detected - security risk!")
                return stored_hash == provided_password
            
            else:
                logger.error(f"Unknown hash format: {stored_hash[:20]}...")
                return False
                
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
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
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_data(data: str, salt: str = None) -> str:
        """Hash data with optional salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        combined = salt + data
        hash_object = hashlib.sha256(combined.encode('utf-8'))
        return salt + hash_object.hexdigest()
    
    @staticmethod
    def verify_hash(data: str, stored_hash: str) -> bool:
        """Verify data against stored hash"""
        if len(stored_hash) < 32:
            return False
        
        salt = stored_hash[:32]
        test_hash = SecurityUtils.hash_data(data, salt)
        return test_hash == stored_hash
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        import os
        import re
        
        # Remove directory traversal attempts
        filename = os.path.basename(filename)
        
        # Remove or replace dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
    
    @staticmethod
    def validate_content_type(file, allowed_types: list) -> bool:
        """Validate file content type"""
        import mimetypes
        
        if not file or not file.filename:
            return False
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(file.filename)
        
        return mime_type in allowed_types
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_input_length(data: str, max_length: int = 1000) -> bool:
        """Validate input length to prevent DoS"""
        return len(data) <= max_length
    
    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML characters to prevent XSS"""
        import html
        return html.escape(text)
    
    @staticmethod
    def validate_rate_limit_key(key: str) -> bool:
        """Validate rate limiting key format"""
        import re
        # Allow alphanumeric, hyphens, underscores, dots, colons
        pattern = r'^[a-zA-Z0-9._:-]+$'
        return bool(re.match(pattern, key)) and len(key) <= 100
    
    @staticmethod
    def mask_sensitive_info(data: str, mask_char: str = '*', visible_start: int = 2, visible_end: int = 2) -> str:
        """Mask sensitive information for logging"""
        if not data or len(data) <= (visible_start + visible_end):
            return mask_char * len(data) if data else ''
        
        masked_length = len(data) - visible_start - visible_end
        return data[:visible_start] + mask_char * masked_length + data[-visible_end:]

class PasswordStrengthValidator:
    """Password strength validation"""
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Validate password strength and return detailed feedback"""
        errors = []
        score = 0
        
        # Length check
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        elif len(password) >= 12:
            score += 2
        else:
            score += 1
        
        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not has_lower:
            errors.append("Password must contain at least one lowercase letter")
        else:
            score += 1
        
        if not has_upper:
            errors.append("Password must contain at least one uppercase letter")
        else:
            score += 1
        
        if not has_digit:
            errors.append("Password must contain at least one number")
        else:
            score += 1
        
        if not has_special:
            errors.append("Password must contain at least one special character")
        else:
            score += 1
        
        # Common password check
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
            score = max(0, score - 2)
        
        # Sequential characters check
        if any(password[i:i+3] in '0123456789abcdefghijklmnopqrstuvwxyz' for i in range(len(password)-2)):
            errors.append("Password should not contain sequential characters")
            score = max(0, score - 1)
        
        # Determine strength level
        if score >= 6 and len(errors) == 0:
            strength = "Strong"
        elif score >= 4:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'strength': strength,
            'score': score
        }

# Global security instance
security_utils = SecurityUtils()
password_validator = PasswordStrengthValidator()