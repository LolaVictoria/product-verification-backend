# models/user.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from enum import Enum

class UserRole(Enum):
    ADMIN = "admin"
    MANUFACTURER = "manufacturer"
    CUSTOMER = "customer"

class AccountStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    CANCELLED = "cancelled"

class VerificationStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"

@dataclass
class User:
    """User model for all user types"""
    _id: Optional[ObjectId] = None
    role: UserRole = UserRole.CUSTOMER
    
    # Email fields
    primary_email: str = ""
    emails: List[Dict[str, Any]] = field(default_factory=list)
    email_verified: bool = False
    
    # Authentication
    password_hash: str = ""
    
    # Profile fields
    name: str = ""
    username: str = ""
    
    # Status fields
    verification_status: VerificationStatus = VerificationStatus.PENDING
    account_status: AccountStatus = AccountStatus.ACTIVE
    is_active: bool = True
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    # Role-specific fields (Optional)
    manufacturer_id: Optional[ObjectId] = None
    company_name: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "role": self.role.value,
            "primary_email": self.primary_email,
            "emails": self.emails,
            "email_verified": self.email_verified,
            "password_hash": self.password_hash,
            "name": self.name,
            "username": self.username,
            "verification_status": self.verification_status.value,
            "account_status": self.account_status.value,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login": self.last_login,
            "manufacturer_id": self.manufacturer_id,
            "company_name": self.company_name
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create from database dictionary"""
        return cls(
            _id=data.get("_id"),
            role=UserRole(data.get("role", "customer")),
            primary_email=data.get("primary_email", ""),
            emails=data.get("emails", []),
            email_verified=data.get("email_verified", False),
            password_hash=data.get("password_hash", ""),
            name=data.get("name", ""),
            username=data.get("username", ""),
            verification_status=VerificationStatus(data.get("verification_status", "pending")),
            account_status=AccountStatus(data.get("account_status", "active")),
            is_active=data.get("is_active", True),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            last_login=data.get("last_login"),
            manufacturer_id=data.get("manufacturer_id"),
            company_name=data.get("company_name", "")
        )

class UserSchema:
    """Validation for User model"""
    
    @staticmethod
    def validate_registration(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate user registration data"""
        errors = []
        
        # Required fields
        required_fields = ['email', 'password', 'name']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                errors.append(f"{field} is required")
        
        # Email validation
        email = data.get('email', '').strip().lower()
        if email:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append("Invalid email format")
        
        # Password validation
        password = data.get('password', '')
        if password and len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        # Role validation
        role = data.get('role', 'customer')
        valid_roles = [r.value for r in UserRole]
        if role not in valid_roles:
            errors.append(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'email': email,
                'password': password,
                'name': data.get('name', '').strip(),
                'role': role,
                'username': data.get('username', '').strip()
            }
        }
    
    @staticmethod
    def validate_update(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate user update data"""
        errors = []
        cleaned_data = {}
        
        # Optional email validation
        if 'email' in data:
            email = data['email'].strip().lower()
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append("Invalid email format")
            else:
                cleaned_data['email'] = email
        
        # Optional name validation
        if 'name' in data:
            name = data['name'].strip()
            if len(name) < 1:
                errors.append("Name cannot be empty")
            else:
                cleaned_data['name'] = name
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': cleaned_data
        }
