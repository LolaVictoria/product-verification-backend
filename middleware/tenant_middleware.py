# middleware/tenant_middleware.py
from functools import wraps
from flask import request, jsonify, g
import jwt
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class TenantMiddleware:
    """Middleware for tenant isolation and request routing"""
    
    def __init__(self, app, config: Dict[str, Any], multi_tenant_service, db_manager):
        self.app = app
        self.config = config
        self.multi_tenant_service = multi_tenant_service
        self.db_manager = db_manager
        self.secret_key = config['SECRET_KEY']
    
    def extract_manufacturer_id(self, request) -> Optional[str]:
        """Extract manufacturer ID from request (API key, JWT, or header)"""
        # Try API key first
        api_key = request.headers.get('X-API-Key')
        if api_key:
            manufacturer = self.db_manager.db.manufacturers.find_one({'api_key': api_key})
            if manufacturer:
                return manufacturer['manufacturer_id']
        
        # Try JWT token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                token = auth_header.split(' ')[1]
                payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
                return payload.get('manufacturer_id')
            except jwt.InvalidTokenError:
                pass
        
        # Try manufacturer ID header (for testing)
        return request.headers.get('X-Manufacturer-ID')
    
    def tenant_required(self, f):
        """Decorator to require valid tenant authentication"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            manufacturer_id = self.extract_manufacturer_id(request)
            
            if not manufacturer_id:
                return jsonify({
                    'error': 'Missing manufacturer authentication',
                    'details': 'Provide X-API-Key header or Bearer token'
                }), 401
            
            # Validate tenant access
            client_ip = request.remote_addr or '127.0.0.1'
            endpoint = request.endpoint or 'unknown'
            
            access_result = self.multi_tenant_service.validate_tenant_access(
                manufacturer_id, client_ip, endpoint
            )
            
            if not access_result['allowed']:
                response_data = {
                    'error': 'Access denied',
                    'reason': access_result['reason']
                }
                
                if 'rate_limit_info' in access_result:
                    response_data['rate_limit'] = access_result['rate_limit_info']
                    return jsonify(response_data), 429
                
                return jsonify(response_data), 403
            
            # Store tenant info in Flask's g object for use in route handlers
            g.manufacturer_id = manufacturer_id
            g.manufacturer_config = access_result['manufacturer_config']
            g.rate_limit_info = access_result['rate_limit_info']
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def admin_required(self, f):
        """Decorator to require admin access"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check admin authentication
            admin_token = request.headers.get('X-Admin-Token')
            
            if not admin_token or admin_token != self.config.get('ADMIN_TOKEN'):
                return jsonify({'error': 'Admin access required'}), 403
            
            # Store admin info in g
            g.is_admin = True
            
            return f(*args, **kwargs)
        
        return decorated_function

