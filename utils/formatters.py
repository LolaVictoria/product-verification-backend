from typing import Dict, Any, List, Optional
import json
from datetime import datetime

def create_cors_response(data: Any = None, status_code: int = 200, headers: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Create a response with CORS headers for API endpoints.
    
    Args:
        data (Any): Response data
        status_code (int): HTTP status code
        headers (Dict[str, str]): Additional headers
        
    Returns:
        Dict[str, Any]: Formatted response with CORS headers
    """
    default_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Max-Age': '86400'
    }
    
    if headers:
        default_headers.update(headers)
    
    return {
        'statusCode': status_code,
        'headers': default_headers,
        'body': json.dumps(data) if data is not None else json.dumps({})
    }

def format_user_response(user_data: Dict[str, Any], include_sensitive: bool = False) -> Dict[str, Any]:
    """
    Format user data for API response, excluding sensitive information.
    
    Args:
        user_data (Dict[str, Any]): Raw user data
        include_sensitive (bool): Whether to include sensitive data
        
    Returns:
        Dict[str, Any]: Formatted user data
    """
    safe_fields = [
        'id', 'username', 'email', 'first_name', 'last_name', 
        'created_at', 'updated_at', 'is_active', 'role'
    ]
    
    formatted_user = {}
    
    for field in safe_fields:
        if field in user_data:
            formatted_user[field] = user_data[field]
    
    # Include sensitive data only if explicitly requested
    if include_sensitive:
        sensitive_fields = ['last_login', 'login_count', 'api_key_hash']
        for field in sensitive_fields:
            if field in user_data:
                formatted_user[field] = user_data[field]
    
    return formatted_user

def create_success_response(data: Any = None, message: str = "Operation successful") -> Dict[str, Any]:
    """
    Create a standardized success response.
    
    Args:
        data (Any): Response data
        message (str): Success message
        
    Returns:
        Dict[str, Any]: Formatted success response
    """
    response = {
        'success': True,
        'message': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    if data is not None:
        response['data'] = data
    
    return response

def create_error_response(error: str, error_code: str = None, details: Any = None) -> Dict[str, Any]:
    """
    Create a standardized error response.
    
    Args:
        error (str): Error message
        error_code (str): Error code for categorization
        details (Any): Additional error details
        
    Returns:
        Dict[str, Any]: Formatted error response
    """
    response = {
        'success': False,
        'error': error,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    if error_code:
        response['error_code'] = error_code
    
    if details is not None:
        response['details'] = details
    
    return response

def format_product_response(product_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format product data for API response.
    
    Args:
        product_data (Dict[str, Any]): Raw product data
        
    Returns:
        Dict[str, Any]: Formatted product data
    """
    formatted_product = {
        'id': product_data.get('id'),
        'name': product_data.get('name'),
        'model': product_data.get('model'),
        'manufacturer': {
            'id': product_data.get('manufacturer_id'),
            'name': product_data.get('manufacturer_name')
        },
        'category': product_data.get('category'),
        'description': product_data.get('description'),
        'specifications': product_data.get('specifications', {}),
        'price': product_data.get('price'),
        'availability': product_data.get('availability', 'unknown'),
        'created_at': product_data.get('created_at'),
        'updated_at': product_data.get('updated_at')
    }
    
    # Remove None values
    return {k: v for k, v in formatted_product.items() if v is not None}

def format_device_details(device_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format device details for API response.
    
    Args:
        device_data (Dict[str, Any]): Raw device data
        
    Returns:
        Dict[str, Any]: Formatted device details
    """
    formatted_device = {
        'device_id': device_data.get('device_id'),
        'serial_number': device_data.get('serial_number'),
        'product': {
            'id': device_data.get('product_id'),
            'name': device_data.get('product_name'),
            'model': device_data.get('model')
        },
        'manufacturer': {
            'id': device_data.get('manufacturer_id'),
            'name': device_data.get('manufacturer_name')
        },
        'status': device_data.get('status', 'unknown'),
        'firmware_version': device_data.get('firmware_version'),
        'last_seen': device_data.get('last_seen'),
        'location': device_data.get('location'),
        'configuration': device_data.get('configuration', {}),
        'telemetry': device_data.get('telemetry', {}),
        'created_at': device_data.get('created_at'),
        'updated_at': device_data.get('updated_at')
    }
    
    # Remove None values
    return {k: v for k, v in formatted_device.items() if v is not None}

def format_api_response(success: bool, data: Any = None, error: str = None, 
                       status_code: int = None) -> Dict[str, Any]:
    """
    Format a complete API response with proper structure.
    
    Args:
        success (bool): Whether the operation was successful
        data (Any): Response data (for success responses)
        error (str): Error message (for error responses)
        status_code (int): HTTP status code
        
    Returns:
        Dict[str, Any]: Complete formatted API response
    """
    if success:
        response_data = create_success_response(data)
        default_status = 200
    else:
        response_data = create_error_response(error or "An error occurred")
        default_status = 400
    
    return create_cors_response(
        data=response_data,
        status_code=status_code or default_status
    )