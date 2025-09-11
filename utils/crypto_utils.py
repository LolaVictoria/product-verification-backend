import secrets
import hashlib
import string

def generate_api_key(length: int = 32) -> str:
    """
    Generate a secure API key using cryptographically secure random generation.
    
    Args:
        length (int): Length of the API key. Default is 32 characters.
        
    Returns:
        str: A secure API key string
    """
    # Use alphanumeric characters and some special characters for API key
    characters = string.ascii_letters + string.digits
    api_key = ''.join(secrets.choice(characters) for _ in range(length))
    return api_key

def hash_api_key(api_key: str, salt: str = None) -> str:
    """
    Hash an API key using SHA-256 with optional salt for secure storage.
    
    Args:
        api_key (str): The API key to hash
        salt (str, optional): Salt to add to the hash. If None, generates a random salt.
        
    Returns:
        str: Hashed API key (salt + hash if salt was generated)
    """
    if salt is None:
        # Generate a random salt
        salt = secrets.token_hex(16)
    
    # Combine salt and API key
    salted_key = salt + api_key
    
    # Create SHA-256 hash
    hash_object = hashlib.sha256(salted_key.encode('utf-8'))
    hashed_key = hash_object.hexdigest()
    
    # Return salt + hash for storage (first 32 chars are salt)
    return salt + hashed_key

def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """
    Verify an API key against its stored hash.
    
    Args:
        api_key (str): The API key to verify
        stored_hash (str): The stored hash (salt + hash)
        
    Returns:
        bool: True if API key matches, False otherwise
    """
    if len(stored_hash) < 32:
        return False
    
    # Extract salt (first 32 characters)
    salt = stored_hash[:32]
    
    # Hash the provided API key with the extracted salt
    test_hash = hash_api_key(api_key, salt)
    
    # Compare with stored hash
    return test_hash == stored_hash