from typing import Dict, Any, Optional
import re
from email_validator import validate_email, EmailNotValidError

class ValidatorService:
    
    @staticmethod
    def validate_manufacturer_profile(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate manufacturer profile updates (existing manufacturers)
        
        Args:
            data (Dict[str, Any]): Manufacturer data to validate
            
        Returns:
            Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
        """
        errors = []
        required_fields = ['name', 'email', 'contact_person', 'address']
        
        # Check required fields
        for field in required_fields:
            if not data.get(field) or str(data.get(field)).strip() == '':
                errors.append(f"'{field}' is required")
        
        # Validate email format
        if data.get('email'):
            try:
                validate_email(data['email'])
            except EmailNotValidError:
                errors.append("Invalid email format")
        
        # Validate name length
        if data.get('name') and len(data['name']) < 2:
            errors.append("Manufacturer name must be at least 2 characters long")
        
        # Validate phone if provided
        if data.get('phone'):
            phone_pattern = r'^\+?[\d\s\-\(\)]{10,}$'
            if not re.match(phone_pattern, data['phone']):
                errors.append("Invalid phone number format")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    @staticmethod
    def validate_integration_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate integration request data.
        
        Args:
            data (Dict[str, Any]): Integration request data to validate
            
        Returns:
            Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
        """
        errors = []
        required_fields = ['manufacturer_id', 'integration_type', 'api_endpoint']
        
        # Check required fields
        for field in required_fields:
            if not data.get(field):
                errors.append(f"'{field}' is required")
        
        # Validate integration type
        valid_types = ['REST_API', 'WEBHOOK', 'MQTT', 'WEBSOCKET']
        if data.get('integration_type') and data['integration_type'] not in valid_types:
            errors.append(f"Integration type must be one of: {', '.join(valid_types)}")
        
        # Validate API endpoint URL
        if data.get('api_endpoint'):
            url_pattern = r'^https?://[\w\-\.]+\.[a-zA-Z]{2,}(/.*)?$'
            if not re.match(url_pattern, data['api_endpoint']):
                errors.append("Invalid API endpoint URL format")
        
        # Validate manufacturer_id is numeric
        if data.get('manufacturer_id') and not str(data['manufacturer_id']).isdigit():
            errors.append("Manufacturer ID must be numeric")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    @staticmethod
    def validate_user_registration(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate user registration data.
        
        Args:
            data (Dict[str, Any]): User registration data to validate
            
        Returns:
            Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
        """
        errors = []
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
        
        # Check required fields
        for field in required_fields:
            if not data.get(field) or str(data.get(field)).strip() == '':
                errors.append(f"'{field}' is required")
        
        # Validate email format
        if data.get('email'):
            try:
                validate_email(data['email'])
            except EmailNotValidError:
                errors.append("Invalid email format")
        
        # Validate username
        if data.get('username'):
            if len(data['username']) < 3:
                errors.append("Username must be at least 3 characters long")
            if not re.match(r'^[a-zA-Z0-9_]+$', data['username']):
                errors.append("Username can only contain letters, numbers, and underscores")
        
        # Validate password strength
        if data.get('password'):
            password = data['password']
            if len(password) < 8:
                errors.append("Password must be at least 8 characters long")
            if not re.search(r'[A-Z]', password):
                errors.append("Password must contain at least one uppercase letter")
            if not re.search(r'[a-z]', password):
                errors.append("Password must contain at least one lowercase letter")
            if not re.search(r'[0-9]', password):
                errors.append("Password must contain at least one number")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors.append("Password must contain at least one special character")
        
        # Validate name fields
        for field in ['first_name', 'last_name']:
            if data.get(field) and len(data[field]) < 2:
                errors.append(f"{field.replace('_', ' ').title()} must be at least 2 characters long")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    @staticmethod
    def validate_login_data(data: Dict[str, Any]) -> Optional[str]:
        """Validate login data"""
        if not data:
            return "No data provided"
        
        # Check for email (not username)
        if not data.get('email'):
            return "Email is required"
        
        if not data.get('password'):
            return "Password is required"
        
        # Validate email format
        email = data.get('email', '').strip()
        if not ValidatorService.is_valid_email(email):
            return "Please enter a valid email address"
        
        # Validate password length
        password = data.get('password', '')
        if len(password) < 6:
            return "Password must be at least 6 characters long"
        
        return None

    @staticmethod
    def validate_user_registration(data: Dict[str, Any]) -> Optional[str]:
        """Validate user registration data"""
        if not data:
            return "No data provided"
        
        required_fields = ['email', 'password', 'username']
        for field in required_fields:
            if not data.get(field):
                return f"{field.title()} is required"
        
        # Validate email format
        email = data.get('email', '').strip()
        if not ValidatorService.is_valid_email(email):
            return "Please enter a valid email address"
        
        # Validate password
        password = data.get('password', '')
        if len(password) < 6:
            return "Password must be at least 6 characters long"
        
        # Validate username
        username = data.get('username', '').strip()
        if len(username) < 3:
            return "Username must be at least 3 characters long"
        
        # Validate role if provided
        role = data.get('role', 'consumer')
        valid_roles = ['consumer', 'manufacturer', 'admin']
        if role not in valid_roles:
            return f"Role must be one of: {', '.join(valid_roles)}"
        
        # Validate manufacturer-specific fields
        if role == 'manufacturer':
            if data.get('wallet_address'):
                wallet_address = data.get('wallet_address', '').strip()
                if not ValidatorService.is_valid_ethereum_address(wallet_address):
                    return "Please enter a valid Ethereum wallet address"
            
            if data.get('company_name'):
                company_name = data.get('company_name', '').strip()
                if len(company_name) < 2:
                    return "Company name must be at least 2 characters long"
        
        return None

    @staticmethod
    def validate_email_update(data: Dict[str, Any]) -> Optional[str]:
        """Validate email update data"""
        if not data:
            return "No data provided"
        
        if not data.get('email'):
            return "Email is required"
        
        email = data.get('email', '').strip()
        if not ValidatorService.is_valid_email(email):
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
    def validate_profile_update(data: Dict[str, Any]) -> Optional[str]:
        """Validate profile update data"""
        if not data:
            return "No data provided"
        
        # Validate email operations
        if 'email_operations' in data:
            for op in data['email_operations']:
                if not isinstance(op, dict):
                    return "Invalid email operation format"
                
                if 'operation' not in op or 'email' not in op:
                    return "Email operations must have 'operation' and 'email' fields"
                
                if op['operation'] not in ['add', 'remove', 'set_primary']:
                    return "Email operation must be 'add', 'remove', or 'set_primary'"
                
                if not ValidatorService.is_valid_email(op['email']):
                    return f"Invalid email address: {op['email']}"
        
        # Validate wallet operations
        if 'wallet_operations' in data:
            for op in data['wallet_operations']:
                if not isinstance(op, dict):
                    return "Invalid wallet operation format"
                
                if 'operation' not in op or 'wallet_address' not in op:
                    return "Wallet operations must have 'operation' and 'wallet_address' fields"
                
                if op['operation'] not in ['add', 'remove', 'set_primary']:
                    return "Wallet operation must be 'add', 'remove', or 'set_primary'"
                
                if not ValidatorService.ValidatorService.is_valid_ethereum_address(op['wallet_address']):
                    return f"Invalid wallet address: {op['wallet_address']}"
        
        # Validate direct updates
        if 'direct_updates' in data:
            direct_updates = data['direct_updates']
            
            if 'primary_email' in direct_updates:
                if not ValidatorService.is_valid_email(direct_updates['primary_email']):
                    return "Invalid primary email address"
            
            if 'primary_wallet' in direct_updates:
                if not ValidatorService.is_valid_ethereum_address(direct_updates['primary_wallet']):
                    return "Invalid primary wallet address"
            
            if 'emails' in direct_updates:
                if not isinstance(direct_updates['emails'], list):
                    return "Emails must be a list"
                
                for email in direct_updates['emails']:
                    if not ValidatorService.is_valid_email(email):
                        return f"Invalid email address in list: {email}"
            
            if 'wallet_addresses' in direct_updates:
                if not isinstance(direct_updates['wallet_addresses'], list):
                    return "Wallet addresses must be a list"
                
                for wallet in direct_updates['wallet_addresses']:
                    if not ValidatorService.is_valid_ethereum_address(wallet):
                        return f"Invalid wallet address in list: {wallet}"
        
        # Validate company name
        if 'company_name' in data:
            company_name = data.get('company_name', '').strip()
            if len(company_name) < 2:
                return "Company name must be at least 2 characters long"
        
        return None
    
validator_service = ValidatorService()

