from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
from bson import ObjectId

@dataclass
class Verification:
    """Verification model"""
    _id: Optional[ObjectId] = None
    serial_number: str = ""
    product_id: Optional[ObjectId] = None
    customer_id: Optional[ObjectId] = None
    manufacturer_id: Optional[ObjectId] = None
    
    # Verification results
    is_authentic: bool = False
    confidence_score: float = 0.0
    source: str = ""  # 'blockchain', 'database', 'not_found'
    
    # Device information
    device_name: str = ""
    device_category: str = ""
    brand: str = ""
    
    # Performance metrics
    response_time: float = 0.0
    verification_method: str = "manual"
    transaction_success: bool = False
    
    # User info
    user_ip: str = ""
    user_role: str = ""
    
    # Metadata
    timestamp: datetime = None
    created_at: datetime = None
    updated_at: datetime = None

class VerificationSchema:
    """Schema validation for Verification model"""
    
    @staticmethod
    def validate_verification(data: Dict) -> Dict:
        """Validate verification data"""
        required_fields = ['serial_number']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data

