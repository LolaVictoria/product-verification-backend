# models/api_key.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from .enums import Enum

class ApiKeyStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"

class ApiKeyEnvironment(Enum):
    SANDBOX = "sandbox"
    PRODUCTION = "production"

@dataclass
class ApiKey:
    """API Key model for manufacturer integrations"""
    _id: Optional[ObjectId] = None
    
    # Key identification
    manufacturer_id: Optional[ObjectId] = None
    name: str = ""
    key_hash: str = ""
    key_prefix: str = ""
    
    # Environment and permissions
    environment: ApiKeyEnvironment = ApiKeyEnvironment.SANDBOX
    permissions: List[str] = field(default_factory=list)
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE
    
    # Rate limiting
    rate_limits: Dict[str, int] = field(default_factory=dict)
    usage_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Usage tracking
    total_requests: int = 0
    requests_today: int = 0
    requests_this_month: int = 0
    last_used: Optional[datetime] = None
    
    # Security
    allowed_ips: List[str] = field(default_factory=list)
    webhook_endpoints: List[str] = field(default_factory=list)
    
    # Metadata
    description: str = ""
    created_by: Optional[ObjectId] = None
    revoked_by: Optional[ObjectId] = None
    revoked_reason: str = ""
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "manufacturer_id": self.manufacturer_id,
            "name": self.name,
            "key_hash": self.key_hash,
            "key_prefix": self.key_prefix,
            "environment": self.environment.value,
            "permissions": self.permissions,
            "status": self.status.value,
            "rate_limits": self.rate_limits,
            "usage_stats": self.usage_stats,
            "total_requests": self.total_requests,
            "requests_today": self.requests_today,
            "requests_this_month": self.requests_this_month,
            "last_used": self.last_used,
            "allowed_ips": self.allowed_ips,
            "webhook_endpoints": self.webhook_endpoints,
            "description": self.description,
            "created_by": self.created_by,
            "revoked_by": self.revoked_by,
            "revoked_reason": self.revoked_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at
        }

class ApiKeySchema:
    """Validation for API Key model"""
    
    @staticmethod
    def validate_creation(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate API key creation data"""
        errors = []
        
        # Required fields
        if not data.get('name') or not str(data.get('name')).strip():
            errors.append("name is required")
        
        # Name validation
        name = data.get('name', '').strip()
        if name and len(name) > 100:
            errors.append("Name cannot exceed 100 characters")
        
        # Permissions validation
        permissions = data.get('permissions', [])
        if not isinstance(permissions, list):
            errors.append("permissions must be an array")
        else:
            valid_permissions = [
                'verify_products',
                'register_products',
                'get_products',
                'transfer_ownership',
                'get_analytics',
                'webhooks',
                'customer_management'
            ]
            for perm in permissions:
                if perm not in valid_permissions:
                    errors.append(f"Invalid permission: {perm}")
        
        # Environment validation
        environment = data.get('environment', 'sandbox')
        if environment not in ['sandbox', 'production']:
            errors.append("Environment must be 'sandbox' or 'production'")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'name': name,
                'permissions': permissions,
                'environment': environment,
                'description': data.get('description', '').strip()
            }
        }

