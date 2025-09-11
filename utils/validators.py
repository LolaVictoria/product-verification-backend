import re
from typing import Dict, Any
from email_validator import validate_email, EmailNotValidError

def validate_manufacturer_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate manufacturer data for registration/updates.
    
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

def validate_login_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate user login data.
    
    Args:
        data (Dict[str, Any]): Login data to validate
        
    Returns:
        Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
    """
    errors = []
    required_fields = ['username', 'password']
    
    # Check required fields
    for field in required_fields:
        if not data.get(field) or str(data.get(field)).strip() == '':
            errors.append(f"'{field}' is required")
    
    # Basic validation - more detailed validation would be done during authentication
    if data.get('username') and len(data['username']) < 3:
        errors.append("Invalid username format")
    
    if data.get('password') and len(data['password']) < 1:
        errors.append("Password cannot be empty")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }