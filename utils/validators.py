import re
from web3 import Web3

def is_valid_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def is_valid_password(password):
    """Validate password strength"""
    if not password or not isinstance(password, str):
        return False
    
    # Minimum 8 characters
    if len(password) < 8:
        return False
    
    # At least one letter and one number
    has_letter = re.search(r'[a-zA-Z]', password)
    has_number = re.search(r'\d', password)
    
    return has_letter and has_number

def is_valid_wallet_address(address):
    """Validate Ethereum wallet address"""
    if not address or not isinstance(address, str):
        return False
    
    try:
        return Web3.is_address(address)
    except Exception:
        return False

def validate_serial_number(serial_number):
    """Validate product serial number format"""
    if not serial_number or not isinstance(serial_number, str):
        return False
    
    # Remove whitespace
    serial_number = serial_number.strip()
    
    # Check length (3-50 characters)
    if len(serial_number) < 3 or len(serial_number) > 50:
        return False
    
    # Only alphanumeric characters and hyphens
    pattern = r'^[a-zA-Z0-9\-]+$'
    return re.match(pattern, serial_number) is not None

def validate_product_name(name):
    """Validate product name"""
    if not name or not isinstance(name, str):
        return False
    
    name = name.strip()
    return 2 <= len(name) <= 100

def validate_category(category):
    """Validate product category"""
    if not category or not isinstance(category, str):
        return False
    
    category = category.strip()
    return 2 <= len(category) <= 50

def validate_pagination(page, per_page, max_per_page=100):
    """Validate pagination parameters"""
    try:
        page = int(page) if page else 1
        per_page = int(per_page) if per_page else 10
        
        if page < 1:
            page = 1
        
        if per_page < 1 or per_page > max_per_page:
            per_page = 10
        
        return page, per_page
    except (ValueError, TypeError):
        return 1, 10

def validate_bulk_serial_numbers(serial_numbers, max_count=100):
    """Validate bulk serial numbers list"""
    if not isinstance(serial_numbers, list):
        return False, "Serial numbers must be a list"
    
    if len(serial_numbers) == 0:
        return False, "Serial numbers list cannot be empty"
    
    if len(serial_numbers) > max_count:
        return False, f"Maximum {max_count} serial numbers allowed"
    
    for serial in serial_numbers:
        if not validate_serial_number(serial):
            return False, f"Invalid serial number: {serial}"
    
    return True, None