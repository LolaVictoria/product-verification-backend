"""
Cryptographic Utilities
Pure functions for cryptographic operations
"""

import hashlib
import secrets
import hmac
import string
from typing import Optional, Tuple, Dict, Any


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token
    
    Args:
        length: Length of token in bytes
        
    Returns:
        URL-safe token string
    """
    return secrets.token_urlsafe(length)

def generate_csrf_token() -> str:
        """Generate CSRF token"""
        return secrets.token_urlsafe(32)

def generate_hex_token(length: int = 32) -> str:
    """
    Generate hex token
    
    Args:
        length: Length in bytes
        
    Returns:
        Hex token string
    """
    return secrets.token_hex(length)


def hash_string(data: str, algorithm: str = 'sha256') -> str:
    """
    Hash string using specified algorithm
    
    Args:
        data: String to hash
        algorithm: Hash algorithm ('sha256', 'sha512', 'md5')
        
    Returns:
        Hex digest of hash
    """
    if algorithm == 'sha256':
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data.encode()).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def hash_data_with_salt(data: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash data with salt
    
    Args:
        data: Data to hash
        salt: Optional salt (generated if not provided)
        
    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    combined = salt + data
    hash_value = hashlib.sha256(combined.encode()).hexdigest()
    
    return hash_value, salt


def verify_hash_with_salt(data: str, stored_hash: str, salt: str) -> bool:
    """
    Verify data against hash with salt
    
    Args:
        data: Data to verify
        stored_hash: Stored hash value
        salt: Salt used in original hash
        
    Returns:
        True if hash matches, False otherwise
    """
    test_hash, _ = hash_data_with_salt(data, salt)
    return hmac.compare_digest(test_hash, stored_hash)


def generate_checksum(data: str) -> str:
    """
    Generate checksum for data validation
    
    Args:
        data: Data to checksum
        
    Returns:
        Checksum string
    """
    return hashlib.md5(data.encode()).hexdigest()[:8]


def verify_checksum(data: str, checksum: str) -> bool:
    """
    Verify data checksum
    
    Args:
        data: Data to verify
        checksum: Expected checksum
        
    Returns:
        True if checksum matches
    """
    calculated = generate_checksum(data)
    return hmac.compare_digest(calculated, checksum)


def create_hmac_signature(data: str, secret: str) -> str:
    """
    Create HMAC signature for data
    
    Args:
        data: Data to sign
        secret: Secret key
        
    Returns:
        HMAC signature (hex)
    """
    signature = hmac.new(
        secret.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    )
    return signature.hexdigest()


def verify_hmac_signature(data: str, signature: str, secret: str) -> bool:
    """
    Verify HMAC signature
    
    Args:
        data: Original data
        signature: Signature to verify
        secret: Secret key
        
    Returns:
        True if signature is valid
    """
    expected = create_hmac_signature(data, secret)
    return hmac.compare_digest(expected, signature)

def generate_verification_token(length: int = 32) -> str:
    """Generate secure verification token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_specification_hash(self, product_data: Dict[str, Any]) -> str:
        """Generate specification hash for blockchain registration"""
        spec_string = f"{product_data.get('brand', '')}{product_data.get('model', '')}{product_data.get('serial_number', '')}{product_data.get('device_type', '')}"
        return "0x" + hashlib.sha256(spec_string.encode()).hexdigest()[:32]


def generate_ethereum_address_checksum(address: str) -> str:
    """
    Generate Ethereum EIP-55 checksum address
    
    Args:
        address: Ethereum address (with or without 0x prefix)
        
    Returns:
        Checksummed address
    """
    # Remove 0x prefix if present
    address = address.replace('0x', '').lower()
    
    # Hash the address
    hash_value = hashlib.sha3_256(address.encode()).hexdigest()
    
    # Apply checksum
    checksum_address = '0x'
    for i, char in enumerate(address):
        if char in '0123456789':
            checksum_address += char
        else:
            # Uppercase if corresponding hash digit is >= 8
            if int(hash_value[i], 16) >= 8:
                checksum_address += char.upper()
            else:
                checksum_address += char
    
    return checksum_address