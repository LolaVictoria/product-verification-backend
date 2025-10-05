import bcrypt
import logging

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

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
    

    # def verify_password(user_id: str, password: str) -> bool:
    #     """
    #     Verify a user's password.
        
    #     Args:
    #         user_id (str): The user ID
    #         password (str): The password to verify
            
    #     Returns:
    #         bool: True if password is correct, False otherwise
    #     """
    #     user = users_db.get(user_id)
    #     if not user:
    #         return False
        
    #     salt = user.get('salt')
    #     stored_hash = user.get('password_hash')
        
    #     if not salt or not stored_hash:
    #         return False
        
    #     # Hash the provided password with the stored salt
    #     password_hash = hashlib.pbkdf2_hmac('sha256', 
    #                                     password.encode('utf-8'), 
    #                                     salt.encode('utf-8'), 
    #                                     100000)
        
    #     return password_hash.hex() == stored_hash


        
    