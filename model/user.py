
# models/user.py
from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
from bson import ObjectId

@dataclass
class User:
    """User model for manufacturers and customers"""
    _id: Optional[ObjectId] = None
    emails: List[str] = None
    primary_email: str = ""
    password_hash: str = ""
    role: str = ""  # 'manufacturer' or 'customer'
    verification_status: str = "pending"  # 'pending', 'verified', 'rejected'
    
    # Manufacturer specific fields
    wallet_addresses: List[str] = None
    primary_wallet: str = ""
    verified_wallets: List[str] = None
    company_names: List[str] = None
    current_company_name: str = ""
    
    # Integration fields
    integration_settings: Dict = None
    api_keys: List[Dict] = None
    webhook_endpoints: List[str] = None
    
    # Metadata
    created_at: datetime = None
    updated_at: datetime = None
    last_login: datetime = None

class UserSchema:
    """Schema validation for User model"""
    
    @staticmethod
    def validate_registration(data: Dict) -> Dict:
        """Validate user registration data"""
        required_fields = ['email', 'password', 'role']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        if data.get('role') == 'manufacturer':
            if not data.get('wallet_address'):
                errors.append("wallet_address is required for manufacturers")
            if not data.get('company_name'):
                errors.append("company_name is required for manufacturers")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data

