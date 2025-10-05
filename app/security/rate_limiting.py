# app/security/rate_limiting.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Redis for rate limiting storage
redis_client = redis.Redis(host='localhost', port=6379, db=0)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["200 per day", "50 per hour"]
)

# Apply to specific endpoints
@limiter.limit("5 per minute")
def verify_product():
    # Verification endpoint
    pass

@limiter.limit("10 per minute") 
def api_authenticate():
    # Authentication endpoint
    pass