import logging
from typing import List
from app.api.middleware.response_middleware import response_middleware
from app.api.middleware.validation_middleware import valiidation_middleware, ValidationError
logger = logging.getLogger(__name__)


class RequestValidator:
    """Validator for authentication-related operations"""    
    @staticmethod
    def validate_json_request(required_fields: List[str] = None):
        """Decorator to validate JSON requests"""
        def decorator(f):
            def wrapper(*args, **kwargs):
                try:
                    from flask import request
                    data = request.get_json()
                    
                    # Validate JSON structure
                    if required_fields:
                        valiidation_middleware.validate_request_data(data, required_fields)
                    
                    # Add validated data to request
                    request.validated_data = data
                    return f(*args, **kwargs)
                    
                except ValidationError as e:
                    return response_middleware.create_error_response(str(e), 400)
                    
            return wrapper
        return decorator

