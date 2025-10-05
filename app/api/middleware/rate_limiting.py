# middleware/rate_limiting.py
import time
import redis
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, g
from functools import wraps
import hashlib
import json
from app.config.database import get_db_connection

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.use_database = redis_client is None
        
    def _get_client_identifier(self):
        """Get unique identifier for client"""
        # Try to get user ID from token
        user_id = getattr(g, 'current_user_id', None)
        if user_id:
            return f"user:{user_id}"
        
        # Try to get API key identifier
        api_key = request.headers.get('X-API-Key')
        if api_key:
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"api_key:{api_key_hash}"
        
        # Fall back to IP address
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        return f"ip:{ip}"
    
    def _get_redis_key(self, identifier, endpoint, window_type):
        """Generate Redis key for rate limiting"""
        return f"rate_limit:{window_type}:{endpoint}:{identifier}"
    
    def _check_rate_limit_redis(self, key, limit, window_seconds):
        """Check rate limit using Redis"""
        try:
            pipe = self.redis_client.pipeline()
            now = time.time()
            
            # Remove expired entries
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = pipe.execute()
            current_count = results[1]
            
            return current_count < limit, current_count
            
        except Exception as e:
            print(f"Redis rate limiting error: {e}")
            return True, 0  # Allow request if Redis fails
    
    def _check_rate_limit_database(self, identifier, endpoint, limit, window_minutes):
        """Check rate limit using database"""
        try:
            db = get_db_connection()
            if not db:
                return True, 0
            
            # Calculate window start time
            window_start = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
            
            # Count requests in current window
            current_count = db.rate_limit_logs.count_documents({
                'identifier': identifier,
                'endpoint': endpoint,
                'timestamp': {'$gte': window_start}
            })
            
            # Log current request
            db.rate_limit_logs.insert_one({
                'identifier': identifier,
                'endpoint': endpoint,
                'timestamp': datetime.now(timezone.utc),
                'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            })
            
            # Cleanup old entries (optional, can be done by background job)
            cleanup_time = datetime.now(timezone.utc) - timedelta(hours=24)
            db.rate_limit_logs.delete_many({
                'timestamp': {'$lt': cleanup_time}
            })
            
            return current_count < limit, current_count
            
        except Exception as e:
            print(f"Database rate limiting error: {e}")
            return True, 0
    
    def check_rate_limit(self, endpoint, limits):
        """
        Check multiple rate limits
        limits = {
            'per_minute': 60,
            'per_hour': 1000,
            'per_day': 10000
        }
        """
        identifier = self._get_client_identifier()
        
        for window, limit in limits.items():
            if self.redis_client:
                # Use Redis for high-performance rate limiting
                window_seconds = {
                    'per_minute': 60,
                    'per_hour': 3600,
                    'per_day': 86400
                }.get(window, 60)
                
                key = self._get_redis_key(identifier, endpoint, window)
                allowed, current_count = self._check_rate_limit_redis(key, limit, window_seconds)
                
            else:
                # Use database for simpler deployments
                window_minutes = {
                    'per_minute': 1,
                    'per_hour': 60,
                    'per_day': 1440
                }.get(window, 1)
                
                allowed, current_count = self._check_rate_limit_database(
                    identifier, endpoint, limit, window_minutes
                )
            
            if not allowed:
                return False, {
                    'window': window,
                    'limit': limit,
                    'current': current_count,
                    'identifier': identifier
                }
        
        return True, None

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(limits):
    """
    Rate limiting decorator
    Usage: @rate_limit({'per_minute': 10, 'per_hour': 100})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            endpoint = request.endpoint or f.__name__
            
            allowed, limit_info = rate_limiter.check_rate_limit(endpoint, limits)
            
            if not allowed:
                response_data = {
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Limit: {limit_info["limit"]} per {limit_info["window"].replace("per_", "")}',
                    'limit': limit_info['limit'],
                    'window': limit_info['window'],
                    'current_usage': limit_info['current'],
                    'retry_after': 60 if limit_info['window'] == 'per_minute' else 3600
                }
                
                response = jsonify(response_data)
                response.status_code = 429
                response.headers['X-RateLimit-Limit'] = str(limit_info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(max(0, limit_info['limit'] - limit_info['current']))
                response.headers['X-RateLimit-Reset'] = str(int(time.time()) + (60 if limit_info['window'] == 'per_minute' else 3600))
                response.headers['Retry-After'] = str(60 if limit_info['window'] == 'per_minute' else 3600)
                
                return response
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def api_rate_limit(limits):
    """
    API-specific rate limiting with enhanced headers
    Usage: @api_rate_limit({'per_minute': 100, 'per_hour': 1000})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            endpoint = request.endpoint or f.__name__
            
            allowed, limit_info = rate_limiter.check_rate_limit(endpoint, limits)
            
            if not allowed:
                response_data = {
                    'success': False,
                    'error': {
                        'code': 'RATE_LIMIT_EXCEEDED',
                        'message': f'API rate limit exceeded. Maximum {limit_info["limit"]} requests per {limit_info["window"].replace("per_", "")}',
                        'details': {
                            'limit': limit_info['limit'],
                            'window': limit_info['window'],
                            'current_usage': limit_info['current'],
                            'identifier_type': limit_info['identifier'].split(':')[0]
                        }
                    },
                    'retry_after': 60 if limit_info['window'] == 'per_minute' else 3600
                }
                
                response = jsonify(response_data)
                response.status_code = 429
                
                # Add comprehensive rate limit headers
                response.headers['X-RateLimit-Limit'] = str(limit_info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(max(0, limit_info['limit'] - limit_info['current']))
                response.headers['X-RateLimit-Reset'] = str(int(time.time()) + (60 if limit_info['window'] == 'per_minute' else 3600))
                response.headers['X-RateLimit-Window'] = limit_info['window'].replace('per_', '')
                response.headers['Retry-After'] = str(60 if limit_info['window'] == 'per_minute' else 3600)
                
                return response
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class DynamicRateLimiter:
    """Dynamic rate limiter that adjusts limits based on user type"""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.rate_limiter = RateLimiter(redis_client)
    
    def get_user_limits(self, user_role, endpoint_type='default'):
        """Get rate limits based on user role and endpoint type"""
        limits_config = {
            'manufacturer': {
                'default': {'per_minute': 60, 'per_hour': 1000, 'per_day': 10000},
                'verification': {'per_minute': 100, 'per_hour': 2000, 'per_day': 20000},
                'registration': {'per_minute': 30, 'per_hour': 500, 'per_day': 5000}
            },
            'customer': {
                'default': {'per_minute': 30, 'per_hour': 500, 'per_day': 5000},
                'verification': {'per_minute': 50, 'per_hour': 1000, 'per_day': 10000}
            },
            'anonymous': {
                'default': {'per_minute': 10, 'per_hour': 100, 'per_day': 1000},
                'verification': {'per_minute': 20, 'per_hour': 200, 'per_day': 2000}
            }
        }
        
        return limits_config.get(user_role, limits_config['anonymous']).get(endpoint_type, limits_config['anonymous']['default'])

def dynamic_rate_limit(endpoint_type='default'):
    """
    Dynamic rate limiting based on user role
    Usage: @dynamic_rate_limit('verification')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine user role
            user_role = getattr(g, 'current_user_role', 'anonymous')
            
            # Get appropriate limits
            dynamic_limiter = DynamicRateLimiter()
            limits = dynamic_limiter.get_user_limits(user_role, endpoint_type)
            
            # Apply rate limiting
            endpoint = request.endpoint or f.__name__
            allowed, limit_info = rate_limiter.check_rate_limit(endpoint, limits)
            
            if not allowed:
                response_data = {
                    'error': 'Rate limit exceeded',
                    'message': f'Rate limit exceeded for {user_role} users',
                    'limit': limit_info['limit'],
                    'window': limit_info['window'],
                    'user_role': user_role,
                    'endpoint_type': endpoint_type
                }
                
                return jsonify(response_data), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

rate_limiter = RateLimiter()
dynamic_rate_limiter = DynamicRateLimiter()