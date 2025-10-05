#validators/product_validator.py
"""
Product Validation
Business-level validation for product operations
"""

from typing import Optional, Dict, Any
import re


class ProductValidator:
    """Validator for product-related operations"""
    
    @staticmethod
    def validate_product_data(product_data: Dict[str, Any]) -> Optional[str]:
        """
        Validate product data for registration
        
        Args:
            product_data: Product data to validate
            
        Returns:
            Error message if validation fails, None if valid
        """
        if not product_data:
            return "Product data is required"
        
        # Required fields
        required_fields = ['serial_number', 'manufacturer_id']
        for field in required_fields:
            if not product_data.get(field):
                return f"{field} is required"
        
        # Validate serial number format
        serial_number = product_data.get('serial_number', '').strip()
        if len(serial_number) < 3:
            return "Serial number must be at least 3 characters long"
        
        if len(serial_number) > 100:
            return "Serial number cannot exceed 100 characters"
        
        # Check for valid characters in serial number
        if not re.match(r'^[A-Za-z0-9\-_]+$', serial_number):
            return "Serial number can only contain letters, numbers, hyphens, and underscores"
        
        # Validate manufacturer_id format (ObjectId format)
        manufacturer_id = product_data.get('manufacturer_id', '').strip()
        if len(manufacturer_id) != 24 or not re.match(r'^[a-fA-F0-9]{24}$', manufacturer_id):
            return "Invalid manufacturer ID format"
        
        # Validate optional fields if present
        if 'brand' in product_data:
            brand = product_data['brand']
            if brand and (len(brand) > 100 or len(brand) < 1):
                return "Brand name must be between 1 and 100 characters"
        
        if 'model' in product_data:
            model = product_data['model']
            if model and (len(model) > 100 or len(model) < 1):
                return "Model name must be between 1 and 100 characters"
        
        if 'device_type' in product_data:
            device_type = product_data['device_type']
            valid_device_types = [
                'smartphone', 'tablet', 'laptop', 'desktop', 'smartwatch',
                'headphones', 'camera', 'gaming_console', 'smart_tv', 'other'
            ]
            if device_type and device_type not in valid_device_types:
                return f"Invalid device type. Must be one of: {', '.join(valid_device_types)}"
        
        # Validate boolean fields
        if 'register_on_blockchain' in product_data:
            if not isinstance(product_data['register_on_blockchain'], bool):
                return "register_on_blockchain must be a boolean value"
        
        return None
    
    @staticmethod
    def validate_ownership_transfer(transfer_data: Dict[str, Any]) -> Optional[str]:
        """
        Validate ownership transfer data
        
        Args:
            transfer_data: Transfer data to validate
            
        Returns:
            Error message if validation fails, None if valid
        """
        if not transfer_data:
            return "Transfer data is required"
        
        # Required fields
        required_fields = ['serial_number', 'new_owner_address', 'transfer_reason']
        for field in required_fields:
            if not transfer_data.get(field):
                return f"{field} is required"
        
        # Validate serial number
        serial_number = transfer_data.get('serial_number', '').strip()
        if len(serial_number) < 3:
            return "Serial number must be at least 3 characters long"
        
        # Validate new owner address (wallet address format)
        new_owner_address = transfer_data.get('new_owner_address', '').strip()
        if len(new_owner_address) < 20:
            return "Invalid owner address format"
        
        # Basic wallet address validation (Ethereum format)
        if not re.match(r'^0x[a-fA-F0-9]{40}$', new_owner_address):
            return "Owner address must be a valid Ethereum wallet address"
        
        # Validate transfer reason
        transfer_reason = transfer_data.get('transfer_reason', '').strip()
        valid_reasons = ['sale', 'gift', 'warranty_replacement', 'trade', 'other']
        if transfer_reason not in valid_reasons:
            return f"Invalid transfer reason. Must be one of: {', '.join(valid_reasons)}"
        
        # Validate sale price if provided
        if 'sale_price' in transfer_data:
            sale_price = transfer_data['sale_price']
            if not isinstance(sale_price, (int, float)) or sale_price < 0:
                return "Sale price must be a non-negative number"
        
        return None
    
    @staticmethod
    def validate_api_key_data(api_key_data: Dict[str, Any]) -> Optional[str]:
        """
        Validate API key creation data
        
        Args:
            api_key_data: API key data to validate
            
        Returns:
            Error message if validation fails, None if valid
        """
        if not api_key_data:
            return "API key data is required"
        
        # Validate name
        name = api_key_data.get('name', '').strip()
        if not name:
            return "API key name is required"
        
        if len(name) > 100:
            return "API key name cannot exceed 100 characters"
        
        # Validate permissions
        permissions = api_key_data.get('permissions', [])
        if not isinstance(permissions, list):
            return "Permissions must be a list"
        
        valid_permissions = ['verify_products', 'register_products', 'transfer_ownership', 'view_analytics']
        for perm in permissions:
            if perm not in valid_permissions:
                return f"Invalid permission: {perm}. Valid permissions are: {', '.join(valid_permissions)}"
        
        return None
product_validator = ProductValidator()