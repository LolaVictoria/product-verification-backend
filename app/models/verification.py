# models/verification.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from enum import Enum

class VerificationResult(Enum):
    AUTHENTIC = "authentic"
    COUNTERFEIT = "counterfeit"
    SUSPICIOUS = "suspicious"
    NOT_FOUND = "not_found"
    ERROR = "error"

class VerificationSource(Enum):
    DATABASE = "database"
    BLOCKCHAIN = "blockchain"
    HYBRID = "hybrid"
    NOT_FOUND = "not_found"

class VerificationMethod(Enum):
    MANUAL = "manual"
    API = "api"
    QR_SCAN = "qr_scan"
    NFC = "nfc"
    BATCH = "batch"

@dataclass
class Verification:
    """Verification model for tracking product verification attempts"""
    _id: Optional[ObjectId] = None
    
    # Product information
    serial_number: str = ""
    product_id: Optional[ObjectId] = None
    product_name: str = ""
    device_name: str = ""
    device_category: str = ""
    brand: str = ""
    model: str = ""
    device_type: str = ""
    
    # Verification results
    is_authentic: bool = False
    result: VerificationResult = VerificationResult.NOT_FOUND
    confidence_score: float = 0.0
    source: VerificationSource = VerificationSource.DATABASE
    verification_method: VerificationMethod = VerificationMethod.MANUAL
    
    # User information
    customer_id: Optional[ObjectId] = None
    customer_email: str = ""
    user_id: Optional[ObjectId] = None
    user_role: str = "anonymous"
    user_ip: str = ""
    user_agent: str = ""
    
    # Manufacturer information
    manufacturer_id: Optional[ObjectId] = None
    manufacturer_name: str = ""
    
    # Performance metrics
    response_time: float = 0.0
    transaction_success: bool = False
    
    # Blockchain information (if applicable)
    blockchain_verified: bool = False
    transaction_hash: str = ""
    block_number: Optional[int] = None
    
    # Location information (with consent)
    location_data: Dict[str, Any] = field(default_factory=dict)
    
    # Additional metadata
    verification_details: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    
    # Timestamps
    timestamp: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "serial_number": self.serial_number,
            "product_id": self.product_id,
            "product_name": self.product_name,
            "device_name": self.device_name,
            "device_category": self.device_category,
            "brand": self.brand,
            "model": self.model,
            "device_type": self.device_type,
            "is_authentic": self.is_authentic,
            "result": self.result.value,
            "confidence_score": self.confidence_score,
            "source": self.source.value,
            "verification_method": self.verification_method.value,
            "customer_id": self.customer_id,
            "customer_email": self.customer_email,
            "user_id": self.user_id,
            "user_role": self.user_role,
            "user_ip": self.user_ip,
            "user_agent": self.user_agent,
            "manufacturer_id": self.manufacturer_id,
            "manufacturer_name": self.manufacturer_name,
            "response_time": self.response_time,
            "transaction_success": self.transaction_success,
            "blockchain_verified": self.blockchain_verified,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "location_data": self.location_data,
            "verification_details": self.verification_details,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

class VerificationSchema:
    """Validation for Verification model"""
    
    @staticmethod
    def validate_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate verification request data"""
        errors = []
        
        # Required fields
        if not data.get('serial_number') or not str(data.get('serial_number')).strip():
            errors.append("serial_number is required")
        
        # Serial number validation
        serial_number = data.get('serial_number', '').strip()
        if serial_number:
            if len(serial_number) < 3:
                errors.append("Serial number must be at least 3 characters")
            elif len(serial_number) > 100:
                errors.append("Serial number cannot exceed 100 characters")
            
            import re
            if not re.match(r'^[A-Za-z0-9\-_]+', serial_number):
                errors.append("Serial number can only contain letters, numbers, hyphens, and underscores")
        
        # Optional customer email validation
        customer_email = data.get('customer_email', '').strip()
        if customer_email:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            if not re.match(email_pattern, customer_email):
                errors.append("Invalid customer email format")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'serial_number': serial_number.upper(),
                'customer_email': customer_email.lower() if customer_email else '',
                'verification_method': data.get('verification_method', 'manual')
            }
        }
    
    @staticmethod
    def validate_batch_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate batch verification request"""
        errors = []
        
        # Check serial_numbers array
        serial_numbers = data.get('serial_numbers', [])
        if not isinstance(serial_numbers, list):
            errors.append("serial_numbers must be an array")
        elif len(serial_numbers) == 0:
            errors.append("serial_numbers array cannot be empty")
        elif len(serial_numbers) > 10:
            errors.append("Maximum 10 serial numbers allowed per batch")
        else:
            # Validate each serial number
            for i, serial in enumerate(serial_numbers):
                if not serial or not str(serial).strip():
                    errors.append(f"Serial number at index {i} is empty")
                elif len(str(serial).strip()) < 3:
                    errors.append(f"Serial number at index {i} must be at least 3 characters")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'serial_numbers': [str(s).strip().upper() for s in serial_numbers] if isinstance(serial_numbers, list) else [],
                'customer_email': data.get('customer_email', '').strip().lower()
            }
        }