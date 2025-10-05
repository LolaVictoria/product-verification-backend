# validators/auth_validator.py
"""
Authentication Input Validation
Business-level validation for authentication operations
"""

from typing import Optional, Dict, Any
import re


class AuthValidator:
    """Validator for authentication-related operations"""
    
    @staticmethod
    def validate_login_data(data: Dict[str, Any]) -> Optional[str]:
        """
        Validate login credentials
        
        Args:
            data: Login data containing email and password
            
        Returns:
            Error message if validation fails, None if valid
        """
        if not data:
            return "No data provided"
        
        # Check for email (not username)
        if not data.get('email'):
            return "Email is required"
        
        if not data.get('password'):
            return "Password is required"
        
        # Validate email format
        email = data.get('email', '').strip()
        if not AuthValidator._is_valid_email(email):
            return "Please enter a valid email address"
        
        # Validate password length
        password = data.get('password', '')
        if len(password) < 6:
            return "Password must be at least 6 characters long"
        
        return None
    
    @staticmethod
    def validate_registration_data(data: Dict[str, Any]) -> Optional[str]:
        """
        Validate user registration data
        
        Args:
            data: Registration data
            
        Returns:
            Error message if validation fails, None if valid
        """
        if not data:
            return "No data provided"
        
        required_fields = ['email', 'password']
        for field in required_fields:
            if not data.get(field):
                return f"{field.title()} is required"
        
        # Validate email format
        email = data.get('email', '').strip()
        if not AuthValidator._is_valid_email(email):
            return "Please enter a valid email address"
        
        # Validate password
        password = data.get('password', '')
        if len(password) < 6:
            return "Password must be at least 6 characters long"
        
        # Validate role if provided
        role = data.get('role', 'consumer')
        valid_roles = ['consumer', 'manufacturer', 'admin', 'customer']
        if role not in valid_roles:
            return f"Role must be one of: {', '.join(valid_roles)}"
        
        return None
    
    @staticmethod
    def validate_email_update(data: Dict[str, Any]) -> Optional[str]:
        """Validate email update data"""
        if not data:
            return "No data provided"
        
        if not data.get('email'):
            return "Email is required"
        
        email = data.get('email', '').strip()
        if not AuthValidator._is_valid_email(email):
            return "Please enter a valid email address"
        
        return None
    
    @staticmethod
    def validate_password_change(data: Dict[str, Any]) -> Optional[str]:
        """Validate password change data"""
        if not data:
            return "No data provided"
        
        if not data.get('current_password'):
            return "Current password is required"
        
        if not data.get('new_password'):
            return "New password is required"
        
        new_password = data.get('new_password', '')
        if len(new_password) < 6:
            return "New password must be at least 6 characters long"
        
        # Check if new password is different from current
        if data.get('current_password') == new_password:
            return "New password must be different from current password"
        
        return None
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Validate password strength
        
        Returns:
            Dict with 'valid' bool, 'errors' list, 'strength' string, 'score' int
        """
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
        if any(password[i:i+3] in '0123456789abcdefghijklmnopqrstuvwxyz' 
               for i in range(len(password)-2)):
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
    
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Check if email format is valid"""
        if not email or not isinstance(email, str):
            return False
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email.strip()) is not None