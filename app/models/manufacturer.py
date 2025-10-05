# models/manufacturer.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from .user import VerificationStatus, AccountStatus

@dataclass
class Manufacturer:
    """Manufacturer model for B2B customers"""
    _id: Optional[ObjectId] = None
    manufacturer_id: str = ""  # External unique ID
    
    # Company information
    company_name: str = ""
    company_names: List[Dict[str, Any]] = field(default_factory=list)
    current_company_name: str = ""
    
    # Contact information
    contact_name: str = ""
    contact_email: str = ""
    primary_email: str = ""
    emails: List[Dict[str, Any]] = field(default_factory=list)
    phone: str = ""
    
    # Business details
    industry: str = ""
    company_size: str = ""
    website: str = ""
    country: str = ""
    headquarters: str = ""
    established_year: Optional[int] = None
    annual_production: Optional[int] = None
    
    # Wallet/Blockchain
    wallet_addresses: List[Dict[str, Any]] = field(default_factory=list)
    primary_wallet: str = ""
    verified_wallets: List[str] = field(default_factory=list)
    
    # Status
    verification_status: VerificationStatus = VerificationStatus.PENDING
    account_status: AccountStatus = AccountStatus.ACTIVE
    is_active: bool = True
    is_verified: bool = False
    
    # Subscription/Trial
    subscription_status: str = "trial"
    subscription_plan: str = "trial"
    trial_starts: Optional[datetime] = None
    trial_expires: Optional[datetime] = None
    
    # Integration settings
    api_keys: List[Dict[str, Any]] = field(default_factory=list)
    webhook_url: str = ""
    webhook_secret: str = ""
    integration_settings: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    verification_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "manufacturer_id": self.manufacturer_id,
            "company_name": self.company_name,
            "company_names": self.company_names,
            "current_company_name": self.current_company_name,
            "contact_name": self.contact_name,
            "contact_email": self.contact_email,
            "primary_email": self.primary_email,
            "emails": self.emails,
            "phone": self.phone,
            "industry": self.industry,
            "company_size": self.company_size,
            "website": self.website,
            "country": self.country,
            "headquarters": self.headquarters,
            "established_year": self.established_year,
            "annual_production": self.annual_production,
            "wallet_addresses": self.wallet_addresses,
            "primary_wallet": self.primary_wallet,
            "verified_wallets": self.verified_wallets,
            "verification_status": self.verification_status.value,
            "account_status": self.account_status.value,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "subscription_status": self.subscription_status,
            "subscription_plan": self.subscription_plan,
            "trial_starts": self.trial_starts,
            "trial_expires": self.trial_expires,
            "api_keys": self.api_keys,
            "webhook_url": self.webhook_url,
            "webhook_secret": self.webhook_secret,
            "integration_settings": self.integration_settings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "verification_date": self.verification_date
        }

class ManufacturerSchema:
    """Validation for Manufacturer model"""
    
    @staticmethod
    def validate_registration(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate manufacturer registration data"""
        errors = []
        
        # Required fields
        required_fields = ['company_name', 'contact_email', 'contact_name']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                errors.append(f"{field} is required")
        
        # Email validation
        contact_email = data.get('contact_email', '').strip().lower()
        if contact_email:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, contact_email):
                errors.append("Invalid email format")
        
        # Company name validation
        company_name = data.get('company_name', '').strip()
        if company_name and len(company_name) < 2:
            errors.append("Company name must be at least 2 characters")
        
        # Wallet address validation (optional)
        wallet_address = data.get('wallet_address', '').strip()
        if wallet_address:
            wallet_pattern = r'^0x[a-fA-F0-9]{40}$'
            if not re.match(wallet_pattern, wallet_address):
                errors.append("Invalid Ethereum wallet address format")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'company_name': company_name,
                'contact_email': contact_email,
                'contact_name': data.get('contact_name', '').strip(),
                'industry': data.get('industry', '').strip(),
                'website': data.get('website', '').strip(),
                'country': data.get('country', '').strip(),
                'wallet_address': wallet_address
            }
        }
