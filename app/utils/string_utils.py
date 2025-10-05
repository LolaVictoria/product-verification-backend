"""
String Manipulation Utilities
Pure functions for string operations
"""

import re
import html
from typing import Optional


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import os
    
    # Remove directory traversal attempts
    filename = os.path.basename(filename)
    
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename


def mask_sensitive_data(data: str, visible_chars: int = 4, mask_char: str = '*') -> str:
    """
    Mask sensitive data showing only first few characters
    
    Args:
        data: Sensitive data to mask
        visible_chars: Number of characters to show at start
        mask_char: Character to use for masking
        
    Returns:
        Masked string
    """
    if not data or len(data) <= visible_chars:
        return mask_char * len(data) if data else ''
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


def mask_email(email: str) -> str:
    """
    Mask email address for privacy
    
    Args:
        email: Email address
        
    Returns:
        Masked email (e.g., "j***@example.com")
    """
    if not email or '@' not in email:
        return email
    
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    
    if len(username) <= 2:
        masked_username = username[0] + '*'
    else:
        masked_username = username[0] + '*' * (len(username) - 1)
    
    return f"{masked_username}@{domain}"


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length with suffix
    
    Args:
        text: Text to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def slugify(text: str) -> str:
    """
    Convert text to URL-friendly slug
    
    Args:
        text: Text to slugify
        
    Returns:
        URL-friendly slug
    """
    # Convert to lowercase
    text = text.lower()
    
    # Remove special characters
    text = re.sub(r'[^\w\s-]', '', text)
    
    # Replace whitespace with hyphens
    text = re.sub(r'[-\s]+', '-', text)
    
    # Remove leading/trailing hyphens
    text = text.strip('-')
    
    return text


def escape_html_entities(text: str) -> str:
    """
    Escape HTML entities to prevent XSS
    
    Args:
        text: Text to escape
        
    Returns:
        Escaped text
    """
    if not text:
        return ""
    
    return html.escape(text)


def unescape_html_entities(text: str) -> str:
    """
    Unescape HTML entities
    
    Args:
        text: Text to unescape
        
    Returns:
        Unescaped text
    """
    if not text:
        return ""
    
    return html.unescape(text)


def camel_to_snake(text: str) -> str:
    """
    Convert camelCase to snake_case
    
    Args:
        text: camelCase string
        
    Returns:
        snake_case string
    """
    # Insert underscore before uppercase letters
    text = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', text)
    # Insert underscore before uppercase letters that follow lowercase
    text = re.sub('([a-z0-9])([A-Z])', r'\1_\2', text)
    return text.lower()


def snake_to_camel(text: str) -> str:
    """
    Convert snake_case to camelCase
    
    Args:
        text: snake_case string
        
    Returns:
        camelCase string
    """
    components = text.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def remove_extra_whitespace(text: str) -> str:
    """
    Remove extra whitespace from text
    
    Args:
        text: Text with possible extra whitespace
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""
    
    # Replace multiple whitespace with single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove leading/trailing whitespace
    return text.strip()


def normalize_phone_number(phone: str) -> str:
    """
    Normalize phone number by removing non-digits
    
    Args:
        phone: Phone number string
        
    Returns:
        Normalized phone number (digits only)
    """
    if not phone:
        return ""
    
    return re.sub(r'\D', '', phone)

def format_phone_number(phone: str, country_code: str = '+1') -> str:
    """
    Format phone number with country code
    
    Args:
        phone: Phone number
        country_code: Country code (default: +1 for US)
        
    Returns:
        Formatted phone number
    """
    digits = normalize_phone_number(phone)
    
    if len(digits) == 10:
        return f"{country_code} ({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    elif len(digits) == 11 and digits[0] == '1':
        return f"{country_code} ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    else:
        return phone  # Return original if format unclear

def mask_sensitive_info(data: str, mask_char: str = '*', visible_start: int = 2, visible_end: int = 2) -> str:
        """Mask sensitive information for logging"""
        if not data or len(data) <= (visible_start + visible_end):
            return mask_char * len(data) if data else ''
        
        masked_length = len(data) - visible_start - visible_end
        return data[:visible_start] + mask_char * masked_length + data[-visible_end:]

def generate_random_string(length: int = 16, charset: str = 'alphanumeric') -> str:
    """
    Generate random string
    
    Args:
        length: Length of string
        charset: Character set ('alphanumeric', 'alpha', 'numeric', 'hex')
        
    Returns:
        Random string
    """
    import secrets
    import string
    
    if charset == 'alphanumeric':
        chars = string.ascii_letters + string.digits
    elif charset == 'alpha':
        chars = string.ascii_letters
    elif charset == 'numeric':
        chars = string.digits
    elif charset == 'hex':
        chars = string.hexdigits.lower()
    else:
        chars = string.ascii_letters + string.digits
    
    return ''.join(secrets.choice(chars) for _ in range(length))