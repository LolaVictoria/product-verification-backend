#middleware/response_middleware
from flask import request, jsonify, make_response, current_app
from functools import wraps
from typing import Dict, Optional, Any
from datetime import datetime, timezone
import logging
from flask import request, jsonify
logger = logging.getLogger(__name__)

class ResponseMiddleware:
    
    @staticmethod       
    def create_error_response(message: str, status_code: int = 400, details: Optional[Dict] = None) -> make_response:
        """
        Unified error response with consistent format
        """
        error_data = {
            'status': 'error',
            'error': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'path': request.path,
            'method': request.method
        }
        
        if details:
            error_data['details'] = details
        
        logger.error(f"API Error: {message} - {request.method} {request.path}")
        return ResponseMiddleware.create_cors_response(error_data, status_code)

    @staticmethod
    def create_success_response(data: Dict[Any, Any], message: str = "Success", status_code: int = 200) -> make_response:
        """
        Unified success response with consistent format
        """
        response_data = {
            'status': 'success',
            'message': message,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return ResponseMiddleware.create_cors_response(response_data, status_code)

    @staticmethod
    def create_cors_response(data, status_code=200):
        """Unified CORS response helper"""
        response = make_response(jsonify(data), status_code)
        
        allowed_origins = [
            'http://localhost:3000',
            'http://localhost:5173',
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
    

response_middleware = ResponseMiddleware()

 