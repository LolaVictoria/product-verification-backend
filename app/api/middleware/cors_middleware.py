#middleware/cors_middleware
from flask import request, jsonify, make_response, current_app
from functools import wraps
import logging
from flask import request, jsonify
from functools import wraps
from app.api.middleware.auth_middleware import auth_middleware 
logger = logging.getLogger(__name__)

class CorsMiddleware:
    
    @staticmethod
    def add_cors_headers(response):
        """Add CORS headers to a response"""
        allowed_origins = [
            'http://localhost:3000',
            'http://localhost:5173',  # Your frontend URL
            'https://blockchain-verification-esup.vercel.app'
        ]
        
        origin = request.headers.get('Origin')
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = allowed_origins[0]
        
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-API-Key'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    
    @staticmethod
    def handle_preflight(f):
        """Handle OPTIONS preflight requests"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'OPTIONS':
                response = make_response()
                return auth_middleware.add_cors_headers(response)
            return f(*args, **kwargs)
        return decorated
    

cors_middleware = CorsMiddleware()

 