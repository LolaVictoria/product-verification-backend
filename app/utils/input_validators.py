# utils/input_validators.py
"""
Pure Input Validation Utilities
Low-level validation functions with no business logic
"""

import re
from typing import Optional, List
from app.utils.formatters import format_file_size

def is_valid_email(email: str) -> bool:
    """
    Check if email format is valid
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email.strip()) is not None


def is_valid_ethereum_address(address: str) -> bool:
    """
    Check if Ethereum address format is valid
    
    Args:
        address: Ethereum wallet address
        
    Returns:
        True if valid, False otherwise
    """
    if not address or not isinstance(address, str):
        return False
    
    # Ethereum address pattern: 0x followed by 40 hexadecimal characters
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return re.match(pattern, address.strip()) is not None


def is_valid_username(username: str) -> bool:
    """
    Check if username format is valid
    
    Args:
        username: Username to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not username or not isinstance(username, str):
        return False
    
    username = username.strip()
    
    # Username rules: 3-50 characters, alphanumeric and underscores only
    if len(username) < 3 or len(username) > 50:
        return False
    
    pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(pattern, username) is not None


def is_valid_object_id(obj_id: str) -> bool:
    """
    Check if MongoDB ObjectId format is valid
    
    Args:
        obj_id: ObjectId string
        
    Returns:
        True if valid, False otherwise
    """
    if not obj_id or not isinstance(obj_id, str):
        return False
    
    # ObjectId pattern: 24 hexadecimal characters
    pattern = r'^[a-fA-F0-9]{24}$'
    return re.match(pattern, obj_id.strip()) is not None


def sanitize_string(text: str, max_length: int = 255) -> str:
    """
    Sanitize string input to prevent XSS
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        ValueError: If input exceeds max_length
    """
    if not text:
        return ""
    
    import html
    
    # Remove HTML tags and entities
    cleaned = html.escape(text.strip())
    
    # Limit length
    if len(cleaned) > max_length:
        raise ValueError(f"Input too long. Maximum {max_length} characters.")
    
    return cleaned

def validate_file_upload(file, allowed_extensions: List[str], max_size: int = 5 * 1024 * 1024) -> Optional[str]:
        """Validate uploaded file"""
        if not file or not file.filename:
            return "No file provided"
        
        # Check file extension
        if '.' not in file.filename:
            return "File must have an extension"
        
        ext = file.filename.rsplit('.', 1)[1].lower()
        if ext not in allowed_extensions:
            return f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > max_size:
            return f"File too large. Maximum size: {format_file_size(max_size)}"
        
        return None

def validate_serial_number(serial: str) -> str:
    """
    Validate and sanitize serial number
    
    Args:
        serial: Product serial number
        
    Returns:
        Sanitized serial number
        
    Raises:
        ValueError: If serial number is invalid
    """
    if not serial:
        raise ValueError("Serial number is required")
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[^\w\-_]', '', serial.strip())
    
    if len(sanitized) < 3:
        raise ValueError("Serial number must be at least 3 characters")
    
    if len(sanitized) > 50:
        raise ValueError("Serial number too long (max 50 characters)")
    
    # Check for SQL injection patterns
    sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', '--', ';']
    lower_serial = sanitized.lower()
    for pattern in sql_patterns:
        if pattern in lower_serial:
            raise ValueError("Invalid characters in serial number")
    
    return sanitized


def validate_pagination_params(page: any, limit: any, max_limit: int = 100) -> tuple:
    """
    Validate and normalize pagination parameters
    
    Args:
        page: Page number
        limit: Items per page
        max_limit: Maximum allowed limit
        
    Returns:
        Tuple of (page, limit, error_message)
    """
    try:
        page = int(page) if page else 1
        limit = int(limit) if limit else 10
        
        if page < 1:
            return 1, 10, "Page number must be at least 1"
        
        if limit < 1 or limit > max_limit:
            return page, 10, f"Limit must be between 1 and {max_limit}"
        
        return page, limit, None
        
    except (ValueError, TypeError):
        return 1, 10, "Invalid pagination parameters"


def prevent_xss(input_text: str) -> str:
    """
    Prevent XSS attacks by escaping HTML
    
    Args:
        input_text: User input text
        
    Returns:
        Escaped text safe for output
    """
    if not input_text:
        return ""
    
    import html
    
    # Escape HTML entities
    escaped = html.escape(input_text)
    
    # Remove potentially dangerous patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
    ]
    
    for pattern in dangerous_patterns:
        escaped = re.sub(pattern, '', escaped, flags=re.IGNORECASE | re.DOTALL)
    
    return escaped