# models/counterfeit_report.py
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from bson import ObjectId
from .enums import Enum
class ReportStatus(Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"

@dataclass
class CounterfeitReport:
    """Counterfeit report model"""
    _id: Optional[ObjectId] = None
    
    # Related verification
    verification_id: Optional[ObjectId] = None
    product_id: Optional[ObjectId] = None
    manufacturer_id: Optional[ObjectId] = None
    customer_id: Optional[ObjectId] = None
    
    # Product information
    serial_number: str = ""
    product_name: str = ""
    device_category: str = ""
    brand: str = ""
    model: str = ""
    
    # Location information (with consent)
    customer_consent: bool = False
    store_name: str = ""
    store_address: str = ""
    city: str = ""
    state: str = ""
    country: str = ""
    
    # Purchase information
    purchase_date: Optional[datetime] = None
    purchase_price: Optional[float] = None
    receipt_available: bool = False
    
    # Additional details
    additional_notes: str = ""
    suspected_source: str = ""
    report_reason: str = ""
    
    # Investigation details
    report_status: ReportStatus = ReportStatus.PENDING
    investigation_notes: str = ""
    assigned_to: Optional[ObjectId] = None
    resolution_details: str = ""
    
    # Evidence
    evidence_files: List[str] = field(default_factory=list)
    photos: List[str] = field(default_factory=list)
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "verification_id": self.verification_id,
            "product_id": self.product_id,
            "manufacturer_id": self.manufacturer_id,
            "customer_id": self.customer_id,
            "serial_number": self.serial_number,
            "product_name": self.product_name,
            "device_category": self.device_category,
            "brand": self.brand,
            "model": self.model,
            "customer_consent": self.customer_consent,
            "store_name": self.store_name,
            "store_address": self.store_address,
            "city": self.city,
            "state": self.state,
            "country": self.country,
            "purchase_date": self.purchase_date,
            "purchase_price": self.purchase_price,
            "receipt_available": self.receipt_available,
            "additional_notes": self.additional_notes,
            "suspected_source": self.suspected_source,
            "report_reason": self.report_reason,
            "report_status": self.report_status.value,
            "investigation_notes": self.investigation_notes,
            "assigned_to": self.assigned_to,
            "resolution_details": self.resolution_details,
            "evidence_files": self.evidence_files,
            "photos": self.photos,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved_at": self.resolved_at
        }

class CounterfeitReportSchema:
    """Validation for CounterfeitReport model"""
    
    @staticmethod
    def validate_report(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate counterfeit report data"""
        errors = []
        
        # Required fields
        required_fields = ['serial_number', 'product_name', 'device_category', 'customer_id']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                errors.append(f"{field} is required")
        
        # Customer consent for location data
        customer_consent = data.get('customer_consent', False)
        if not isinstance(customer_consent, bool):
            errors.append("customer_consent must be true or false")
        
        # Purchase price validation
        if 'purchase_price' in data and data['purchase_price']:
            try:
                price = float(data['purchase_price'])
                if price < 0:
                    errors.append("Purchase price cannot be negative")
            except (ValueError, TypeError):
                errors.append("Purchase price must be a valid number")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'serial_number': data.get('serial_number', '').strip().upper(),
                'product_name': data.get('product_name', '').strip(),
                'device_category': data.get('device_category', '').strip(),
                'customer_consent': customer_consent,
                'store_name': data.get('store_name', '').strip() if customer_consent else '',
                'store_address': data.get('store_address', '').strip() if customer_consent else '',
                'city': data.get('city', '').strip() if customer_consent else '',
                'state': data.get('state', '').strip() if customer_consent else '',
                'purchase_price': float(data['purchase_price']) if data.get('purchase_price') else None,
                'additional_notes': data.get('additional_notes', '').strip()
            }
        }

