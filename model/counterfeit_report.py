from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
from bson import ObjectId

@dataclass
class CounterfeitReport:
    """Counterfeit report model"""
    _id: Optional[ObjectId] = None
    verification_id: ObjectId = None
    product_id: Optional[ObjectId] = None
    manufacturer_id: Optional[ObjectId] = None
    customer_id: ObjectId = None
    
    # Product info
    serial_number: str = ""
    product_name: str = ""
    device_category: str = ""
    
    # Location info (with consent)
    customer_consent: bool = False
    store_name: str = ""
    store_address: str = ""
    city: str = ""
    state: str = ""
    
    # Purchase info
    purchase_date: Optional[datetime] = None
    purchase_price: float = 0.0
    additional_notes: str = ""
    
    # Report status
    report_status: str = "pending"  # 'pending', 'verified', 'resolved'
    
    # Metadata
    created_at: datetime = None
    updated_at: datetime = None

class CounterfeitReportSchema:
    """Schema validation for CounterfeitReport model"""
    
    @staticmethod
    def validate_report(data: Dict) -> Dict:
        """Validate counterfeit report data"""
        required_fields = ['serial_number', 'product_name', 'device_category', 'customer_id']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data

