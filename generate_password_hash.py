#!/usr/bin/env python3
"""
Utility script to generate bcrypt password hash for admin user
Usage: python generate_password_hash.py
"""
import bcrypt
import getpass

def generate_password_hash():
    """Generate bcrypt hash for admin password"""
    print("Admin Password Hash Generator")
    print("=" * 30)
    
    while True:
        password = getpass.getpass("Enter admin password: ")
        confirm_password = getpass.getpass("Confirm admin password: ")
        
        if password != confirm_password:
            print("Passwords don't match. Please try again.\n")
            continue
        
        if len(password) < 8:
            print("Password must be at least 8 characters long. Please try again.\n")
            continue
        
        break
    
    # Generate hash
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    hash_str = password_hash.decode('utf-8')
    print("\nGenerated Password Hash:")
    print("=" * 30)
    print(hash_str) 