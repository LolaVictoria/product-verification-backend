
# models/product.py
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from enum import Enum

class ProductStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONTINUED = "discontinued"

class BlockchainStatus(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    NOT_REGISTERED = "not_registered"

class RegistrationType(Enum):
    DATABASE = "database"
    BLOCKCHAIN_PENDING = "blockchain_pending"
    BLOCKCHAIN_CONFIRMED = "blockchain_confirmed"
    BLOCKCHAIN_FAILED = "blockchain_failed"

@dataclass
class Product:
    """Product model for verification system"""
    _id: Optional[ObjectId] = None
    
    # Product identification
    serial_number: str = ""
    brand: str = ""
    model: str = ""
    name: str = ""
    device_type: str = ""
    category: str = ""
    product_type: str = ""
    
    # Product details
    description: str = ""
    specifications: Dict[str, Any] = field(default_factory=dict)
    storage_data: str = ""
    color: str = ""
    batch_number: str = ""
    manufacturing_date: Optional[datetime] = None
    warranty_months: Optional[int] = None
    warranty_info: Dict[str, Any] = field(default_factory=dict)
    price: Optional[float] = None
    
    # Manufacturer info
    manufacturer_id: Optional[ObjectId] = None
    manufacturer_name: str = ""
    manufacturer_wallet: str = ""
    current_owner: str = ""
    
    # Blockchain info
    blockchain_status: BlockchainStatus = BlockchainStatus.NOT_REGISTERED
    blockchain_verified: bool = False
    registration_type: RegistrationType = RegistrationType.DATABASE
    transaction_hash: str = ""
    blockchain_hash: str = ""
    block_number: Optional[int] = None
    blockchain_network: str = ""
    confirmed_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    blockchain_error: str = ""
    
    # Ownership and transfers
    ownership_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Cryptographic verification
    public_key: str = ""
    signature: str = ""
    specification_hash: str = ""
    
    # Status
    status: ProductStatus = ProductStatus.ACTIVE
    is_active: bool = True
    
    # Timestamps
    registered_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "_id": self._id,
            "serial_number": self.serial_number,
            "brand": self.brand,
            "model": self.model,
            "name": self.name,
            "device_type": self.device_type,
            "category": self.category,
            "product_type": self.product_type,
            "description": self.description,
            "specifications": self.specifications,
            "storage_data": self.storage_data,
            "color": self.color,
            "batch_number": self.batch_number,
            "manufacturing_date": self.manufacturing_date,
            "warranty_months": self.warranty_months,
            "warranty_info": self.warranty_info,
            "price": self.price,
            "manufacturer_id": self.manufacturer_id,
            "manufacturer_name": self.manufacturer_name,
            "manufacturer_wallet": self.manufacturer_wallet,
            "current_owner": self.current_owner,
            "blockchain_status": self.blockchain_status.value,
            "blockchain_verified": self.blockchain_verified,
            "registration_type": self.registration_type.value,
            "transaction_hash": self.transaction_hash,
            "blockchain_hash": self.blockchain_hash,
            "block_number": self.block_number,
            "blockchain_network": self.blockchain_network,
            "confirmed_at": self.confirmed_at,
            "failed_at": self.failed_at,
            "blockchain_error": self.blockchain_error,
            "ownership_history": self.ownership_history,
            "public_key": self.public_key,
            "signature": self.signature,
            "specification_hash": self.specification_hash,
            "status": self.status.value,
            "is_active": self.is_active,
            "registered_at": self.registered_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

class ProductSchema:
    """Validation for Product model"""
    
    @staticmethod
    def validate_registration(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate product registration data"""
        errors = []
        
        # Required fields
        required_fields = ['serial_number', 'manufacturer_id']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                errors.append(f"{field} is required")
        
        # Serial number validation
        serial_number = data.get('serial_number', '').strip()
        if serial_number:
            if len(serial_number) < 3:
                errors.append("Serial number must be at least 3 characters")
            elif len(serial_number) > 100:
                errors.append("Serial number cannot exceed 100 characters")
            
            import re
            if not re.match(r'^[A-Za-z0-9\-_]+$', serial_number):
                errors.append("Serial number can only contain letters, numbers, hyphens, and underscores")
        
        # Manufacturer ID validation
        manufacturer_id = data.get('manufacturer_id', '').strip()
        if manufacturer_id and not ObjectId.is_valid(manufacturer_id):
            errors.append("Invalid manufacturer ID format")
        
        # Optional field validations
        if 'price' in data:
            try:
                price = float(data['price'])
                if price < 0:
                    errors.append("Price cannot be negative")
            except (ValueError, TypeError):
                errors.append("Price must be a valid number")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'serial_number': serial_number.upper(),
                'manufacturer_id': ObjectId(manufacturer_id) if ObjectId.is_valid(manufacturer_id) else None,
                'brand': data.get('brand', '').strip(),
                'model': data.get('model', '').strip(),
                'device_type': data.get('device_type', '').strip(),
                'description': data.get('description', '').strip(),
                'price': float(data['price']) if data.get('price') else None,
                'register_on_blockchain': data.get('register_on_blockchain', False)
            }
        }
    
    @staticmethod
    def validate_transfer(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate ownership transfer data"""
        errors = []
        
        # Required fields
        required_fields = ['serial_number', 'new_owner_address', 'transfer_reason']
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                errors.append(f"{field} is required")
        
        # Wallet address validation
        new_owner_address = data.get('new_owner_address', '').strip()
        if new_owner_address:
            import re
            wallet_pattern = r'^0x[a-fA-F0-9]{40}$'
            if not re.match(wallet_pattern, new_owner_address):
                errors.append("Invalid wallet address format")
        
        # Transfer reason validation
        valid_reasons = ['sale', 'gift', 'warranty_replacement', 'trade', 'other']
        transfer_reason = data.get('transfer_reason', '').strip().lower()
        if transfer_reason and transfer_reason not in valid_reasons:
            errors.append(f"Invalid transfer reason. Must be one of: {', '.join(valid_reasons)}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'cleaned_data': {
                'serial_number': data.get('serial_number', '').strip().upper(),
                'new_owner_address': new_owner_address,
                'transfer_reason': transfer_reason,
                'sale_price': float(data['sale_price']) if data.get('sale_price') else 0.0,
                'notes': data.get('notes', '').strip()
            }
        }
