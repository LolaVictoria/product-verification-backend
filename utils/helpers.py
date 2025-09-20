import secrets
import string
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from bson import ObjectId

def generate_api_key(length: int = 32) -> str:
    """Generate secure API key"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def hash_api_key(api_key: str, salt: str = None) -> str:
    """Hash API key with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    salted_key = salt + api_key
    hash_object = hashlib.sha256(salted_key.encode('utf-8'))
    hashed_key = hash_object.hexdigest()
    
    return salt + hashed_key

def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Verify API key against stored hash"""
    if len(stored_hash) < 32:
        return False
    
    salt = stored_hash[:32]
    test_hash = hash_api_key(api_key, salt)
    return test_hash == stored_hash

def format_user_response(user: Dict[str, Any]) -> Dict[str, Any]:
    """Format user data for API response"""
    if not user:
        return {}
    
    formatted = {
        "id": str(user.get("_id", "")),
        "role": user.get("role", ""),
        "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
        "updated_at": user.get("updated_at").isoformat() if user.get("updated_at") else None,
        "verification_status": user.get("verification_status", "pending")
    }
    
    if user.get('role') == 'manufacturer':
        formatted.update({
            "name": user.get("name"),
            "primary_email": user.get("primary_email"),
            "emails": user.get("emails", []),
            "company_name": user.get("current_company_name"),
            "company_names": user.get("company_names", []),
            "wallet_addresses": user.get("wallet_addresses", []),
            "primary_wallet": user.get("primary_wallet"),
            "verified_wallets": user.get("verified_wallets", [])
        })
    else:
        formatted.update({
            "username": user.get("username"),
            "email": user.get("email"),
            "wallet_address": user.get("wallet_address")
        })
    
    return formatted

def format_product_response(product: Dict[str, Any]) -> Dict[str, Any]:
    """Format product data for API response"""
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

def sanitize_input(data: str) -> str:
    """Sanitize string input"""
    if not isinstance(data, str):
        return str(data)
    return data.strip()

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def is_valid_ethereum_address(address: str) -> bool:
    """Validate Ethereum address format"""
    if not address or not isinstance(address, str):
        return False
    
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return re.match(pattern, address.strip()) is not None

def is_valid_username(username: str) -> bool:
    """Validate username format"""
    if not username or not isinstance(username, str):
        return False
    
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return False
    
    pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(pattern, username) is not None

def generate_specification_hash(product_data: Dict[str, Any]) -> str:
    """Generate specification hash for blockchain registration"""
    spec_string = f"{product_data.get('brand', '')}{product_data.get('model', '')}{product_data.get('serial_number', '')}{product_data.get('device_type', '')}"
    return "0x" + hashlib.sha256(spec_string.encode()).hexdigest()[:32]

def convert_object_ids(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert ObjectId instances to strings in dictionary"""
    if isinstance(data, dict):
        return {key: convert_object_ids(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_object_ids(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data

def get_client_ip(request) -> str:
    """Get client IP address from request"""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

def get_user_agent(request) -> str:
    """Get user agent from request"""
    return request.headers.get('User-Agent', '')

def paginate_query(query, page: int = 1, limit: int = 20, max_limit: int = 100):
    """Apply pagination to MongoDB query"""
    page = max(1, int(page))
    limit = min(max_limit, max(1, int(limit)))
    skip = (page - 1) * limit
    
    return query.skip(skip).limit(limit), {
        'page': page,
        'limit': limit,
        'skip': skip
    }

def build_filter_query(filters: Dict[str, Any]) -> Dict[str, Any]:
    """Build MongoDB filter query from parameters"""
    query = {}
    
    # Text search
    if filters.get('search'):
        search_term = filters['search']
        query['$or'] = [
            {'serial_number': {'$regex': search_term, '$options': 'i'}},
            {'brand': {'$regex': search_term, '$options': 'i'}},
            {'model': {'$regex': search_term, '$options': 'i'}},
            {'manufacturer_name': {'$regex': search_term, '$options': 'i'}}
        ]
    
    # Date range filter
    if filters.get('start_date') or filters.get('end_date'):
        date_filter = {}
        
        if filters.get('start_date'):
            try:
                start_date = datetime.fromisoformat(filters['start_date'].replace('Z', '+00:00'))
                date_filter['$gte'] = start_date
            except ValueError:
                pass
        
        if filters.get('end_date'):
            try:
                end_date = datetime.fromisoformat(filters['end_date'].replace('Z', '+00:00'))
                date_filter['$lte'] = end_date
            except ValueError:
                pass
        
        if date_filter:
            query['created_at'] = date_filter
    
    # Category filter
    if filters.get('category'):
        query['device_type'] = filters['category']
    
    # Registration type filter
    if filters.get('registration_type'):
        query['registration_type'] = filters['registration_type']
    
    # Manufacturer filter
    if filters.get('manufacturer_id'):
        query['manufacturer_id'] = filters['manufacturer_id']
    
    return query

def calculate_success_rate(successful: int, total: int) -> float:
    """Calculate success rate percentage"""
    if total == 0:
        return 0.0
    return round((successful / total) * 100, 1)

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"

def generate_verification_token(length: int = 32) -> str:
    """Generate secure verification token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """Mask sensitive data showing only first few characters"""
    if not data or len(data) <= visible_chars:
        return data
    
    return data[:visible_chars] + '*' * (len(data) - visible_chars)

def validate_file_upload(file, allowed_extensions: List[str], max_size: int = 5 * 1024 * 1024) -> Optional[str]:
    """Validate uploaded file"""
    if not file or not file.filename:
        return "No file provided"
    
    # Check file extension
    if '.' not in file.filename:
        return "File must have an extension"
    
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > max_size:
        return f"File too large. Maximum size: {format_file_size(max_size)}"
    
    return None

def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)

def parse_time_range(time_range: str) -> int:
    """Parse time range string to days"""
    time_ranges = {
        '7d': 7,
        '14d': 14,
        '30d': 30,
        '90d': 90,
        '1y': 365,
        '6m': 180,
        '3m': 90,
        '1m': 30
    }
    return time_ranges.get(time_range, 7)