from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
from bson import ObjectId
@dataclass
class Product:
    """Product model"""
    _id: Optional[ObjectId] = None
    serial_number: str = ""
    brand: str = ""
    model: str = ""
    device_type: str = ""
    name: str = ""
    description: str = ""
    
    # Manufacturer info
    manufacturer_id: ObjectId = None
    manufacturer_name: str = ""
    manufacturer_wallet: str = ""
    
    # Blockchain info
    blockchain_verified: bool = False
    transaction_hash: str = ""
    registration_type: str = "database"  # 'blockchain_confirmed', 'blockchain_pending', 'blockchain_failed'
    
    # Additional info
    storage_data: str = ""
    color: str = ""
    batch_number: str = ""
    ownership_history: List[Dict] = None
    
    # Metadata
    registered_at: datetime = None
    created_at: datetime = None
    updated_at: datetime = None

class ProductSchema:
    """Schema validation for Product model"""
    
    @staticmethod
    def validate_product_data(data: Dict) -> Dict:
        """Validate product registration data"""
        required_fields = ['serial_number', 'brand', 'model', 'device_type']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data

