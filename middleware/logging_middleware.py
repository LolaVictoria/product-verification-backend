# middleware/logging_middleware.py
import logging
import time
import json
import os
from datetime import datetime, timezone
from flask import request, g, jsonify
from functools import wraps
from utils.database import get_db_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
def setup_logging():
    """Setup logging configuration for the application"""
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler()  # Console output
        ]
    )
    
    # Create specific loggers
    request_logger = logging.getLogger('requests')
    security_logger = logging.getLogger('security')
    error_logger = logging.getLogger('errors')
    
    # Set levels
    request_logger.setLevel(logging.INFO)
    security_logger.setLevel(logging.WARNING)
    error_logger.setLevel(logging.ERROR)
    
    return {
        'request': request_logger,
        'security': security_logger,
        'error': error_logger
    }

class RequestLogger:
    """Advanced request/response logging with analytics"""
    
    @staticmethod
    def log_request():
        """Log incoming request details"""
        g.start_time = time.time()
        g.request_id = f"req_{int(time.time() * 1000)}"
        
        # Get client info
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Log request details
        request_data = {
            'request_id': g.request_id,
            'method': request.method,
            'path': request.path,
            'client_ip': client_ip,
            'user_agent': user_agent,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'query_params': dict(request.args),
            'headers': dict(request.headers)
        }
        
        # Log request body for POST/PUT requests (exclude sensitive data)
        if request.method in ['POST', 'PUT', 'PATCH'] and request.is_json:
            try:
                body = request.get_json()
                # Remove sensitive fields
                if isinstance(body, dict):
                    filtered_body = {k: v for k, v in body.items() 
                                   if k not in ['password', 'api_key', 'secret']}
                    request_data['body'] = filtered_body
            except:
                request_data['body'] = 'Could not parse JSON body'
        
        logger.info(f"REQUEST: {json.dumps(request_data)}")
        
        # Store in database for analytics
        try:
            db = get_db_connection()
            if db is not None:
                db.request_logs.insert_one({
                    **request_data,
                    'timestamp': datetime.now(timezone.utc)
                })
        except Exception as e:
            logger.error(f"Failed to store request log: {e}")

    @staticmethod
    def log_response(response):
        """Log response details and performance metrics"""
        try:
            # Calculate response time
            response_time = round((time.time() - g.start_time) * 1000, 2)
            
            response_data = {
                'request_id': getattr(g, 'request_id', 'unknown'),
                'status_code': response.status_code,
                'response_time_ms': response_time,
                'content_length': response.content_length,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Log response body for errors or if debug mode
            if response.status_code >= 400:
                try:
                    if response.is_json:
                        response_data['error_details'] = response.get_json()
                except:
                    pass
            
            logger.info(f"RESPONSE: {json.dumps(response_data)}")
            
            # Store analytics data
            try:
                db = get_db_connection()
                if db is not None:
                    # Update request log with response data
                    db.request_logs.update_one(
                        {'request_id': getattr(g, 'request_id', 'unknown')},
                        {'$set': {
                            'status_code': response.status_code,
                            'response_time_ms': response_time,
                            'completed_at': datetime.now(timezone.utc)
                        }}
                    )
                    
                    # Store performance metrics
                    performance_metric = {
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'status_code': response.status_code,
                        'response_time_ms': response_time,
                        'timestamp': datetime.now(timezone.utc),
                        'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                    }
                    db.performance_metrics.insert_one(performance_metric)
                    
            except Exception as e:
                logger.error(f"Failed to store response log: {e}")
                
        except Exception as e:
            logger.error(f"Response logging error: {e}")
        
        return response

def log_api_call(endpoint_name):
    """Decorator for logging specific API calls with custom metadata"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            
            # Log API call start
            api_log = {
                'endpoint': endpoint_name,
                'function': f.__name__,
                'method': request.method,
                'path': request.path,
                'started_at': datetime.now(timezone.utc),
                'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            }
            
            try:
                # Execute the function
                result = f(*args, **kwargs)
                
                # Log successful completion
                api_log.update({
                    'status': 'success',
                    'completed_at': datetime.now(timezone.utc),
                    'duration_ms': round((time.time() - start_time) * 1000, 2)
                })
                
                logger.info(f"API_CALL_SUCCESS: {endpoint_name} - {api_log['duration_ms']}ms")
                
                return result
                
            except Exception as e:
                # Log error
                api_log.update({
                    'status': 'error',
                    'error': str(e),
                    'completed_at': datetime.now(timezone.utc),
                    'duration_ms': round((time.time() - start_time) * 1000, 2)
                })
                
                logger.error(f"API_CALL_ERROR: {endpoint_name} - {str(e)}")
                
                # Store error in database
                try:
                    db = get_db_connection()
                    if db is not None:
                        db.api_errors.insert_one(api_log)
                except:
                    pass
                
                raise
            
            finally:
                # Store API call log
                try:
                    db = get_db_connection()
                    if db is not None:
                        db.api_calls.insert_one(api_log)
                except:
                    pass
                    
        return decorated_function
    return decorator

class SecurityLogger:
    """Log security-related events"""
    
    @staticmethod
    def log_authentication_attempt(email, success, ip_address, user_agent=''):
        """Log authentication attempts"""
        auth_log = {
            'event_type': 'authentication_attempt',
            'email': email,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.now(timezone.utc)
        }
        
        logger.info(f"AUTH_ATTEMPT: {email} - {'SUCCESS' if success else 'FAILED'} from {ip_address}")
        
        try:
            db = get_db_connection()
            if db is not None:
                db.security_logs.insert_one(auth_log)
        except Exception as e:
            logger.error(f"Failed to store auth log: {e}")
    
    @staticmethod
    def log_api_key_usage(api_key_id, endpoint, ip_address):
        """Log API key usage"""
        api_usage_log = {
            'event_type': 'api_key_usage',
            'api_key_id': str(api_key_id),
            'endpoint': endpoint,
            'ip_address': ip_address,
            'timestamp': datetime.now(timezone.utc)
        }
        
        logger.info(f"API_KEY_USAGE: {api_key_id} - {endpoint} from {ip_address}")
        
        try:
            db = get_db_connection()
            if db is not None:
                db.security_logs.insert_one(api_usage_log)
        except Exception as e:
            logger.error(f"Failed to store API usage log: {e}")
    
    @staticmethod
    def log_suspicious_activity(event_type, details, ip_address):
        """Log suspicious activities"""
        suspicious_log = {
            'event_type': event_type,
            'details': details,
            'ip_address': ip_address,
            'timestamp': datetime.now(timezone.utc),
            'severity': 'high'
        }
        
        logger.warning(f"SUSPICIOUS_ACTIVITY: {event_type} - {details} from {ip_address}")
        
        try:
            db = get_db_connection()
            if db is not None:
                db.security_logs.insert_one(suspicious_log)
        except Exception as e:
            logger.error(f"Failed to store suspicious activity log: {e}")

def init_logging_middleware(app):
    """Initialize logging middleware for Flask app"""
    
    @app.before_request
    def before_request_logging():
        RequestLogger.log_request()
    
    @app.after_request
    def after_request_logging(response):
        return RequestLogger.log_response(response)
    
    @app.errorhandler(404)
    def not_found_error(error):
        logger.warning(f"404_ERROR: {request.path} from {request.remote_addr}")
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"500_ERROR: {request.path} - {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
    
    return app
request_logger = RequestLogger()
security_logger = SecurityLogger()