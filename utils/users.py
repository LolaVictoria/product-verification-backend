"""
User utility functions for user management and authentication
"""
from typing import Optional, Dict, Any
from datetime import datetime
import hashlib
import secrets

# Mock database - replace with your actual database implementation
users_db = {}  # {user_id: user_data}
email_index = {}  # {email: user_id}
blacklisted_tokens = set()  # Set of blacklisted JWT tokens


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user by their email address.
    
    Args:
        email (str): The email address to search for
        
    Returns:
        Optional[Dict[str, Any]]: User data if found, None otherwise
    """
    if not email:
        return None
    
    email = email.lower().strip()
    user_id = email_index.get(email)
    
    if user_id and user_id in users_db:
        return users_db[user_id].copy()
    
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user by their user ID.
    
    Args:
        user_id (str): The user ID to search for
        
    Returns:
        Optional[Dict[str, Any]]: User data if found, None otherwise
    """
    if not user_id:
        return None
    
    if user_id in users_db:
        return users_db[user_id].copy()
    
    return None


def create_user(email: str, password: str, **kwargs) -> Dict[str, Any]:
    """
    Create a new user with the provided information.
    
    Args:
        email (str): User's email address
        password (str): User's password (will be hashed)
        **kwargs: Additional user data (name, role, etc.)
        
    Returns:
        Dict[str, Any]: The created user data
        
    Raises:
        ValueError: If email already exists or invalid data provided
    """
    if not email or not password:
        raise ValueError("Email and password are required")
    
    email = email.lower().strip()
    
    # Check if user already exists
    if email in email_index:
        raise ValueError(f"User with email {email} already exists")
    
    # Generate user ID
    user_id = secrets.token_hex(16)
    
    # Hash password (in production, use bcrypt or similar)
    salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', 
                                       password.encode('utf-8'), 
                                       salt.encode('utf-8'), 
                                       100000)
    
    # Create user data
    user_data = {
        'id': user_id,
        'email': email,
        'password_hash': password_hash.hex(),
        'salt': salt,
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat(),
        'is_active': True,
        **kwargs  # Additional fields like name, role, etc.
    }
    
    # Store user
    users_db[user_id] = user_data
    email_index[email] = user_id
    
    # Return user data without sensitive information
    safe_user_data = user_data.copy()
    safe_user_data.pop('password_hash', None)
    safe_user_data.pop('salt', None)
    
    return safe_user_data


def blacklist_token(token: str) -> bool:
    """
    Add a JWT token to the blacklist (for logout/token invalidation).
    
    Args:
        token (str): The JWT token to blacklist
        
    Returns:
        bool: True if token was successfully blacklisted
    """
    if not token:
        return False
    
    blacklisted_tokens.add(token)
    return True


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token is blacklisted.
    
    Args:
        token (str): The JWT token to check
        
    Returns:
        bool: True if token is blacklisted, False otherwise
    """
    return token in blacklisted_tokens


def verify_password(user_id: str, password: str) -> bool:
    """
    Verify a user's password.
    
    Args:
        user_id (str): The user ID
        password (str): The password to verify
        
    Returns:
        bool: True if password is correct, False otherwise
    """
    user = users_db.get(user_id)
    if not user:
        return False
    
    salt = user.get('salt')
    stored_hash = user.get('password_hash')
    
    if not salt or not stored_hash:
        return False
    
    # Hash the provided password with the stored salt
    password_hash = hashlib.pbkdf2_hmac('sha256', 
                                       password.encode('utf-8'), 
                                       salt.encode('utf-8'), 
                                       100000)
    
    return password_hash.hex() == stored_hash


def update_user(user_id: str, **kwargs) -> Optional[Dict[str, Any]]:
    """
    Update user information.
    
    Args:
        user_id (str): The user ID to update
        **kwargs: Fields to update
        
    Returns:
        Optional[Dict[str, Any]]: Updated user data if successful, None otherwise
    """
    if user_id not in users_db:
        return None
    
    # Don't allow direct updates to sensitive fields
    forbidden_fields = {'id', 'password_hash', 'salt', 'created_at'}
    update_data = {k: v for k, v in kwargs.items() if k not in forbidden_fields}
    
    if update_data:
        users_db[user_id].update(update_data)
        users_db[user_id]['updated_at'] = datetime.utcnow().isoformat()
    
    # Return safe user data
    safe_user_data = users_db[user_id].copy()
    safe_user_data.pop('password_hash', None)
    safe_user_data.pop('salt', None)
    
    return safe_user_data


# Example usage and testing functions
if __name__ == "__main__":
    # Test the functions
    print("Testing user utils...")
    
    # Create a user
    user = create_user("test@example.com", "password123", name="Test User")
    print(f"Created user: {user}")
    
    # Get user by email
    found_user = get_user_by_email("test@example.com")
    print(f"Found by email: {found_user}")
    
    # Get user by ID
    found_by_id = get_user_by_id(user['id'])
    print(f"Found by ID: {found_by_id}")
    
    # Test blacklist token
    token = "fake.jwt.token"
    blacklist_token(token)
    print(f"Token blacklisted: {is_token_blacklisted(token)}")