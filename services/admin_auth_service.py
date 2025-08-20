import jwt
import bcrypt
from datetime import datetime, timedelta
from flask import current_app
from models.audit_log import AuditLog

class AuthService:
    """Service for handling authentication logic"""
    
    @staticmethod
    def validate_credentials(email, password):
        """Validate admin credentials"""
        admin_email = current_app.config['ADMIN_EMAIL']
        admin_password_hash = current_app.config['ADMIN_PASSWORD_HASH']
        
        # Development fallback
        if not admin_password_hash:
            admin_password_hash = bcrypt.hashpw(
                'admin123'.encode('utf-8'), 
                bcrypt.gensalt()
            ).decode('utf-8')
            print(f"Development mode: Use password 'admin123' for {admin_email}")
        
        # Validate credentials
        if email != admin_email:
            return False
            
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            admin_password_hash.encode('utf-8')
        )
    
    @staticmethod
    def generate_token(email):
        """Generate JWT token for admin"""
        payload = {
            'email': email,
            'role': 'admin',
            'permissions': ['read', 'write', 'authorize'],
            'exp': datetime.utcnow() + timedelta(
                hours=current_app.config['JWT_EXPIRATION_HOURS']
            )
        }
        
        return jwt.encode(
            payload, 
            current_app.config['SECRET_KEY'], 
            algorithm='HS256'
        )
    
    @staticmethod
    def log_login(email, ip_address):
        """Log admin login attempt"""
        AuditLog.create({
            'action': 'ADMIN_LOGIN',
            'admin_email': email,
            'details': {
                'login_time': datetime.utcnow(),
                'ip': ip_address
            }
        })
    
    @staticmethod
    def log_logout(email, ip_address):
        """Log admin logout"""
        AuditLog.create({
            'action': 'ADMIN_LOGOUT',
            'admin_email': email,
            'details': {
                'logout_time': datetime.utcnow(),
                'ip': ip_address
            }
        })
