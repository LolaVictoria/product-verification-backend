#validators/manufacturer_validator.py
"""
Manufacturer Validation
Business-level validation for manufacturer operations
"""

from typing import  Dict, Any
import re


class ManufacturerValidator:
    """Validator for manufacturer-related operations"""
    
    @staticmethod
    def validate_manufacturer_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate manufacturer registration data
        
        Args:
            user_data: User data to validate
            
        Returns:
            Dict with 'valid' boolean and 'errors' list
        """
        errors = []
        
        if not user_data:
            return {'valid': False, 'errors': ['User data is required']}
        
        # Required fields
        required_fields = ['name', 'email', 'company_name', 'wallet_address']
        for field in required_fields:
            if not user_data.get(field):
                errors.append(f"{field} is required")
        
        # Validate email format
        email = user_data.get('email', '').strip().lower()
        if email:
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                errors.append("Invalid email format")
        
        # Validate name
        name = user_data.get('name', '').strip()
        if name:
            if len(name) < 2:
                errors.append("Name must be at least 2 characters long")
            if len(name) > 100:
                errors.append("Name cannot exceed 100 characters")
            if not re.match(r'^[a-zA-Z\s\-\.]+$', name):
                errors.append("Name can only contain letters, spaces, hyphens, and periods")
        
        # Validate company name
        company_name = user_data.get('company_name', '').strip()
        if company_name:
            if len(company_name) < 2:
                errors.append("Company name must be at least 2 characters long")
            if len(company_name) > 200:
                errors.append("Company name cannot exceed 200 characters")
        
        # Validate wallet address (Ethereum format)
        wallet_address = user_data.get('wallet_address', '').strip()
        if wallet_address:
            if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
                errors.append("Wallet address must be a valid Ethereum address")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    @staticmethod
    def validate_manufacturer_profile(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate manufacturer profile updates
        
        Args:
            data: Manufacturer profile data
            
        Returns:
            Dict with 'valid' boolean and 'errors' list
        """
        errors = []
        
        required_fields = ['name', 'email', 'contact_person', 'address']
        
        # Check required fields
        for field in required_fields:
            if not data.get(field) or str(data.get(field)).strip() == '':
                errors.append(f"'{field}' is required")
        
        # Validate email format
        if data.get('email'):
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, data['email']):
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
        Validate integration request data
        
        Args:
            data: Integration request data
            
        Returns:
            Dict with 'valid' boolean and 'errors' list
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
        
        # Validate manufacturer_id is valid ObjectId format
        if data.get('manufacturer_id'):
            if not re.match(r'^[a-fA-F0-9]{24}$', data['manufacturer_id']):
                errors.append("Invalid manufacturer ID format")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
manufacturer_validator = ManufacturerValidator()