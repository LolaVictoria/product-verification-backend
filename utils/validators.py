import re
from typing import Dict, Any, Optional
from email_validator import validate_email, EmailNotValidError
import jwt
from bson import ObjectId

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
    if not is_valid_email(email):
        return "Please enter a valid email address"
    
    # Validate password length
    password = data.get('password', '')
    if len(password) < 6:
        return "Password must be at least 6 characters long"
    
    return None

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
    if not is_valid_email(email):
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
            if not is_valid_ethereum_address(wallet_address):
                return "Please enter a valid Ethereum wallet address"
        
        if data.get('company_name'):
            company_name = data.get('company_name', '').strip()
            if len(company_name) < 2:
                return "Company name must be at least 2 characters long"
    
    return None

def validate_email_update(data: Dict[str, Any]) -> Optional[str]:
    """Validate email update data"""
    if not data:
        return "No data provided"
    
    if not data.get('email'):
        return "Email is required"
    
    email = data.get('email', '').strip()
    if not is_valid_email(email):
        return "Please enter a valid email address"
    
    return None

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
            
            if not is_valid_email(op['email']):
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
            
            if not is_valid_ethereum_address(op['wallet_address']):
                return f"Invalid wallet address: {op['wallet_address']}"
    
    # Validate direct updates
    if 'direct_updates' in data:
        direct_updates = data['direct_updates']
        
        if 'primary_email' in direct_updates:
            if not is_valid_email(direct_updates['primary_email']):
                return "Invalid primary email address"
        
        if 'primary_wallet' in direct_updates:
            if not is_valid_ethereum_address(direct_updates['primary_wallet']):
                return "Invalid primary wallet address"
        
        if 'emails' in direct_updates:
            if not isinstance(direct_updates['emails'], list):
                return "Emails must be a list"
            
            for email in direct_updates['emails']:
                if not is_valid_email(email):
                    return f"Invalid email address in list: {email}"
        
        if 'wallet_addresses' in direct_updates:
            if not isinstance(direct_updates['wallet_addresses'], list):
                return "Wallet addresses must be a list"
            
            for wallet in direct_updates['wallet_addresses']:
                if not is_valid_ethereum_address(wallet):
                    return f"Invalid wallet address in list: {wallet}"
    
    # Validate company name
    if 'company_name' in data:
        company_name = data.get('company_name', '').strip()
        if len(company_name) < 2:
            return "Company name must be at least 2 characters long"
    
    return None

def is_valid_email(email: str) -> bool:
    """Check if email format is valid"""
    if not email or not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def is_valid_ethereum_address(address: str) -> bool:
    """Check if Ethereum address format is valid"""
    if not address or not isinstance(address, str):
        return False
    
    # Ethereum address pattern: 0x followed by 40 hexadecimal characters
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return re.match(pattern, address.strip()) is not None

def is_valid_username(username: str) -> bool:
    """Check if username format is valid"""
    if not username or not isinstance(username, str):
        return False
    
    username = username.strip()
    
    # Username rules: 3-50 characters, alphanumeric and underscores only
    if len(username) < 3 or len(username) > 50:
        return False
    
    pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(pattern, username) is not None

def sanitize_input(data: str) -> str:
    """Sanitize string input"""
    if not isinstance(data, str):
        return str(data)
    
    return data.strip()


def validate_token(token, secret_key):
    """Validate JWT token and return user info"""
    if not token:
        return None, None, {'message': 'Token is missing!'}, 401
    
    if token.startswith('Bearer '):
        token = token[7:]
        
    try:
        data = jwt.decode(token, secret_key, algorithms=['HS256'])
        if 'sub' not in data or 'role' not in data:
            return None, None, {'message': 'Invalid token: missing required fields'}, 401
        return ObjectId(data['sub']), data['role'], None, None
    except jwt.ExpiredSignatureError:
        return None, None, {'message': 'Token has expired!'}, 401
    except jwt.InvalidTokenError:
        return None, None, {'message': 'Token is invalid!'}, 401
    except Exception:
        return None, None, {'message': 'Token validation failed'}, 401

"""
Validation functions for the application
"""
import re
from typing import Dict, Any, List, Optional


def validate_product_data(product_data: Dict[str, Any]) -> Optional[str]:
    """
    Validate product data for registration
    
    Args:
        product_data (Dict[str, Any]): Product data to validate
        
    Returns:
        Optional[str]: Error message if validation fails, None if valid
    """
    if not product_data:
        return "Product data is required"
    
    # Required fields
    required_fields = ['serial_number', 'manufacturer_id']
    for field in required_fields:
        if not product_data.get(field):
            return f"{field} is required"
    
    # Validate serial number format
    serial_number = product_data.get('serial_number', '').strip()
    if len(serial_number) < 3:
        return "Serial number must be at least 3 characters long"
    
    if len(serial_number) > 100:
        return "Serial number cannot exceed 100 characters"
    
    # Check for valid characters in serial number
    if not re.match(r'^[A-Za-z0-9\-_]+$', serial_number):
        return "Serial number can only contain letters, numbers, hyphens, and underscores"
    
    # Validate manufacturer_id format (assuming ObjectId format)
    manufacturer_id = product_data.get('manufacturer_id', '').strip()
    if len(manufacturer_id) != 24 or not re.match(r'^[a-fA-F0-9]{24}$', manufacturer_id):
        return "Invalid manufacturer ID format"
    
    # Validate optional fields if present
    if 'brand' in product_data:
        brand = product_data['brand']
        if brand and (len(brand) > 100 or len(brand) < 1):
            return "Brand name must be between 1 and 100 characters"
    
    if 'model' in product_data:
        model = product_data['model']
        if model and (len(model) > 100 or len(model) < 1):
            return "Model name must be between 1 and 100 characters"
    
    if 'device_type' in product_data:
        device_type = product_data['device_type']
        valid_device_types = [
            'smartphone', 'tablet', 'laptop', 'desktop', 'smartwatch', 
            'headphones', 'camera', 'gaming_console', 'smart_tv', 'other'
        ]
        if device_type and device_type not in valid_device_types:
            return f"Invalid device type. Must be one of: {', '.join(valid_device_types)}"
    
    # Validate boolean fields
    if 'register_on_blockchain' in product_data:
        if not isinstance(product_data['register_on_blockchain'], bool):
            return "register_on_blockchain must be a boolean value"
    
    return None


def validate_ownership_transfer(transfer_data: Dict[str, Any]) -> Optional[str]:
    """
    Validate ownership transfer data
    
    Args:
        transfer_data (Dict[str, Any]): Transfer data to validate
        
    Returns:
        Optional[str]: Error message if validation fails, None if valid
    """
    if not transfer_data:
        return "Transfer data is required"
    
    # Required fields
    required_fields = ['serial_number', 'new_owner_address', 'transfer_reason']
    for field in required_fields:
        if not transfer_data.get(field):
            return f"{field} is required"
    
    # Validate serial number
    serial_number = transfer_data.get('serial_number', '').strip()
    if len(serial_number) < 3:
        return "Serial number must be at least 3 characters long"
    
    # Validate new owner address (assuming wallet address format)
    new_owner_address = transfer_data.get('new_owner_address', '').strip()
    if len(new_owner_address) < 20:
        return "Invalid owner address format"
    
    # Basic wallet address validation (Ethereum format)
    if not re.match(r'^0x[a-fA-F0-9]{40}$', new_owner_address):
        return "Owner address must be a valid Ethereum wallet address"
    
    # Validate transfer reason
    transfer_reason = transfer_data.get('transfer_reason', '').strip()
    valid_reasons = ['sale', 'gift', 'warranty_replacement', 'trade', 'other']
    if transfer_reason not in valid_reasons:
        return f"Invalid transfer reason. Must be one of: {', '.join(valid_reasons)}"
    
    # Validate sale price if provided
    if 'sale_price' in transfer_data:
        sale_price = transfer_data['sale_price']
        if not isinstance(sale_price, (int, float)) or sale_price < 0:
            return "Sale price must be a non-negative number"
    
    return None


def validate_manufacturer_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate manufacturer registration data
    
    Args:
        user_data (Dict[str, Any]): User data to validate
        
    Returns:
        Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
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


def validate_api_key_data(api_key_data: Dict[str, Any]) -> Optional[str]:
    """
    Validate API key creation data
    
    Args:
        api_key_data (Dict[str, Any]): API key data to validate
        
    Returns:
        Optional[str]: Error message if validation fails, None if valid
    """
    if not api_key_data:
        return "API key data is required"
    
    # Validate name
    name = api_key_data.get('name', '').strip()
    if not name:
        return "API key name is required"
    
    if len(name) > 100:
        return "API key name cannot exceed 100 characters"
    
    # Validate permissions
    permissions = api_key_data.get('permissions', [])
    if not isinstance(permissions, list):
        return "Permissions must be a list"
    
    valid_permissions = ['verify_products', 'register_products', 'transfer_ownership', 'view_analytics']
    for perm in permissions:
        if perm not in valid_permissions:
            return f"Invalid permission: {perm}. Valid permissions are: {', '.join(valid_permissions)}"
    
    return None


def validate_user_login(login_data: Dict[str, Any]) -> Optional[str]:
    """
    Validate user login data
    
    Args:
        login_data (Dict[str, Any]): Login data to validate
        
    Returns:
        Optional[str]: Error message if validation fails, None if valid
    """
    if not login_data:
        return "Login data is required"
    
    # Check for required fields
    email = login_data.get('email', '').strip()
    password = login_data.get('password', '')
    
    if not email:
        return "Email is required"
    
    if not password:
        return "Password is required"
    
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return "Invalid email format"
    
    return None

def validate_pagination_params(page: Any, limit: Any) -> tuple[int, int, Optional[str]]:

    """Validate and normalize pagination parameters"""
    try:
        page = int(page) if page else 1
        limit = int(limit) if limit else 10
        
        if page < 1:
            return 1, 10, "Page number must be at least 1"
        
        if limit < 1 or limit > 100:
            return page, 10, "Limit must be between 1 and 100"
        
        return page, limit, None
        
    except (ValueError, TypeError):
        return 1, 10, "Invalid pagination parameters"
    """
    Validate user login data.
    
    Args:
        data (Dict[str, Any]): Login data to validate
        
    Returns:
        Dict[str, Any]: Validation result with 'valid' boolean and 'errors' list
    """
    errors = []
    required_fields = ['email', 'password']
    
    # Check required fields
    for field in required_fields:
        if not data.get(field) or str(data.get(field)).strip() == '':
            errors.append(f"'{field}' is required")
    
    # Basic validation - more detailed validation would be done during authentication
    if data.get('email') and len(data['email']) < 3:
        errors.append("Invalid email format")
    
    if data.get('password') and len(data['password']) < 1:
        errors.append("Password cannot be empty")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }