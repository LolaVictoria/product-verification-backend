from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
from bson import ObjectId

@dataclass
class ManufacturerIntegration:
    """Manufacturer integration model for platform integrations"""
    _id: Optional[ObjectId] = None
    manufacturer_id: ObjectId = None
    integration_name: str = ""
    platform_type: str = ""  # 'ecommerce', 'erp', 'custom'
    
    # API Configuration
    api_endpoint: str = ""
    api_key_id: str = ""
    webhook_url: str = ""
    webhook_secret: str = ""
    
    # Integration settings
    sync_settings: Dict = None
    data_mapping: Dict = None
    filters: Dict = None
    
    # Status
    status: str = "inactive"  # 'active', 'inactive', 'error'
    last_sync: Optional[datetime] = None
    error_message: str = ""
    
    # Metadata
    created_at: datetime = None
    updated_at: datetime = None

class IntegrationSchema:
    """Schema validation for ManufacturerIntegration model"""
    
    @staticmethod
    def validate_integration(data: Dict) -> Dict:
        """Validate integration data"""
        required_fields = ['manufacturer_id', 'integration_name', 'platform_type']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data