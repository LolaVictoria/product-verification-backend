import json
import logging
import os
from datetime import datetime
from bson import ObjectId

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for MongoDB ObjectId and datetime objects"""
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

def setup_logging(app):
    """Setup application logging"""
    if not app.debug:
        # Production logging
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = logging.FileHandler('logs/product_auth.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Product Auth API startup')

def mask_api_key(api_key, show_chars=8):
    """Mask API key for display purposes"""
    if not api_key or len(api_key) <= show_chars:
        return api_key
    return api_key[:show_chars] + '*' * (len(api_key) - show_chars)  

def format_pagination_response(items, page, per_page, total):
    """Format paginated response"""
    return {
        'data': items,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'has_next': page * per_page < total,
            'has_prev': page > 1
        }
    }

def create_error_response(message, status_code=400, details=None):
    """Create standardized error response"""
    response = {'error': message}
    if details:
        response['details'] = details
    return response, status_code

def create_success_response(message, data=None, status_code=200):
    """Create standardized success response"""
    response = {'message': message}
    if data:
        response.update(data)
    return response, status_code