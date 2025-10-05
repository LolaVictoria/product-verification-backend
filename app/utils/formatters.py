"""
Response Formatting Utilities
Pure functions for formatting data for API responses
"""

from typing import Dict, Any, Optional, List
from datetime import datetime


def format_user_response(user: Dict[str, Any], role: str = None) -> Dict[str, Any]:
    """
    Format user data for API response
    Centralized user formatting - use this everywhere
    
    Args:
        user: Raw user document from database
        role: User role (optional, can be inferred from user doc)
        
    Returns:
        Formatted user dictionary
    """
    if not user:
        return {}
    
    # Base fields for all users
    formatted = {
        "id": str(user.get("_id", "")),
        "role": user.get("role", role),
        "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
        "updated_at": user.get("updated_at").isoformat() if user.get("updated_at") else None,
        "is_active": user.get("is_active", True)
    }
    
    # Role-specific formatting
    user_role = user.get('role') or role
    
    if user_role == 'manufacturer':
        formatted.update({
            "company_name": user.get("current_company_name") or user.get("company_name"),
            "email": user.get("primary_email") or user.get("contact_email"),
            "verification_status": user.get("verification_status", "pending"),
            "manufacturer_id": user.get("manufacturer_id"),
            "wallet_address": user.get("primary_wallet")
        })
    
    elif user_role == 'admin':
        formatted.update({
            "email": user.get("primary_email") or user.get("email"),
            "username": user.get("username"),
            "name": user.get("name")
        })
    
    elif user_role == 'customer':
        formatted.update({
            "email": user.get("primary_email") or user.get("email"),
            "name": user.get("name"),
            "manufacturer_id": str(user.get("manufacturer_id")) if user.get("manufacturer_id") else None
        })
    
    return formatted

def format_product_response(product: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format product data for API response
    
    Args:
        product: Raw product document from database
        
    Returns:
        Formatted product dictionary
    """
    if not product:
        return {}
    
    return {
        "id": str(product.get("_id", "")),
        "serial_number": product.get("serial_number", ""),
        "name": product.get("name") or f"{product.get('brand', '')} {product.get('model', '')}".strip(),
        "brand": product.get("brand", ""),
        "model": product.get("model", ""),
        "device_type": product.get("device_type", ""),
        "category": product.get("category", product.get("device_type", "")),
        "storage_data": product.get("storage_data", ""),
        "color": product.get("color", ""),
        "batch_number": product.get("batch_number", ""),
        "manufacturer_id": str(product.get("manufacturer_id", "")),
        "manufacturer_name": product.get("manufacturer_name", ""),
        "manufacturer_wallet": product.get("manufacturer_wallet", ""),
        "current_owner": product.get("current_owner", ""),
        "price": product.get("price", 0),
        "registration_type": product.get("registration_type", "pending"),
        "blockchain_verified": product.get("blockchain_verified", False),
        "verified": product.get("verified", False),
        "transaction_hash": product.get("transaction_hash", ""),
        "block_number": product.get("block_number"),
        "specification_hash": product.get("specification_hash", ""),
        "created_at": product.get("created_at").isoformat() if product.get("created_at") else None,
        "updated_at": product.get("updated_at").isoformat() if product.get("updated_at") else None
    }

def format_verification_response(verification: Dict[str, Any]) -> Dict[str, Any]:
    """Format verification data for API response"""
    if not verification:
        return {}
    
    return {
        "id": str(verification.get("_id", "")),
        "serial_number": verification.get("serial_number", ""),
        "result": verification.get("result", ""),
        "authentic": verification.get("authentic", False),
        "confidence_score": verification.get("confidence_score", 0),
        "timestamp": verification.get("timestamp").isoformat() if verification.get("timestamp") else None,
        "ip_address": verification.get("ip_address", ""),
        "product_info": verification.get("product_info", {})
    }

def format_api_key_response(api_key: Dict[str, Any], include_key: bool = False) -> Dict[str, Any]:
    """
    Format API key data for response
    
    Args:
        api_key: Raw API key document
        include_key: Whether to include the actual key (only for creation)
        
    Returns:
        Formatted API key dictionary
    """
    if not api_key:
        return {}
    
    formatted = {
        "id": str(api_key.get("_id", "")),
        "name": api_key.get("name", ""),
        "key_prefix": api_key.get("key_prefix", ""),
        "permissions": api_key.get("permissions", []),
        "created_at": api_key.get("created_at").isoformat() if api_key.get("created_at") else None,
        "last_used": api_key.get("last_used").isoformat() if api_key.get("last_used") else None,
        "usage_count": api_key.get("usage_count", 0),
        "revoked": api_key.get("revoked", False)
    }
    
    # Only include full key on creation
    if include_key and api_key.get("api_key"):
        formatted["api_key"] = api_key["api_key"]
    
    return formatted

def format_pagination_response(items: List[Dict], total_count: int, page: int, per_page: int) -> Dict[str, Any]:
    """
    Format paginated response
    
    Args:
        items: List of items for current page
        total_count: Total number of items
        page: Current page number
        per_page: Items per page
        
    Returns:
        Formatted response with pagination metadata
    """
    import math
    
    total_pages = math.ceil(total_count / per_page) if per_page > 0 else 0
    
    return {
        "data": items,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_items": total_count,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
            "next_page": page + 1 if page < total_pages else None,
            "prev_page": page - 1 if page > 1 else None
        }
    }

def format_error_response(error: str, details: Optional[Dict] = None, status_code: int = 400) -> Dict[str, Any]:
    """
    Format error response
    
    Args:
        error: Error message
        details: Optional error details
        status_code: HTTP status code
        
    Returns:
        Formatted error dictionary
    """
    response = {
        "success": False,
        "error": error,
        "status_code": status_code
    }
    
    if details:
        response["details"] = details
    
    return response

def format_success_response(data: Any, message: str = "Success") -> Dict[str, Any]:
    """
    Format success response
    
    Args:
        data: Response data
        message: Success message
        
    Returns:
        Formatted success dictionary
    """
    return {
        "success": True,
        "message": message,
        "data": data
    }

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: File size in bytes
        
    Returns:
        Human readable file size string (e.g., "1.5 MB")
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    
    return f"{size:.1f}{size_names[i]}"

def format_datetime_for_display(dt: datetime, format_string: str = '%Y-%m-%d %H:%M:%S UTC') -> str:
    """
    Format datetime for display
    
    Args:
        dt: Datetime object
        format_string: Format string
        
    Returns:
        Formatted datetime string
    """
    from datetime import timezone
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    
    return dt.strftime(format_string)

def convert_object_ids(data: Any) -> Any:
    """
    Convert ObjectId instances to strings in data structure
    
    Args:
        data: Dictionary, list, or other data structure
        
    Returns:
        Data with ObjectIds converted to strings
    """
    from bson import ObjectId
    
    if isinstance(data, dict):
        return {key: convert_object_ids(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_object_ids(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data