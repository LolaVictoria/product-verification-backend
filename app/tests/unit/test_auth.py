# tests/unit/test_auth.py
import pytest
from app.utils.security import security_utils

def test_password_hashing():
    """Test password hashing and verification"""
    password = "test_password"
    hashed = security_utils.hash_password(password)
    
    assert security_utils.verify_password(hashed, password) == True
    assert security_utils.verify_password(hashed, "wrong_password") == False

def test_jwt_token_generation():
    """Test JWT token generation and verification"""
    from app.utils.security import SecurityUtils
    
    token = SecurityUtils.generate_jwt_token("user123", "admin", "secret", 1)
    result = SecurityUtils.verify_jwt_token(token, "secret")
    
    assert result['valid'] == True
    assert result['payload']['sub'] == "user123"
    assert result['payload']['role'] == "admin"