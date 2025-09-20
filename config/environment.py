# config/environment.py
import os
from typing import Dict, Any
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class FeatureFlags:
    """Feature flags for enterprise vs basic features"""
    def __init__(self, env: Environment):
        self.env = env
        
    @property
    def use_real_hsm(self) -> bool:
        return self.env == Environment.PRODUCTION
    
    @property
    def use_vpc_isolation(self) -> bool:
        return self.env == Environment.PRODUCTION
    
    @property
    def use_cloud_storage(self) -> bool:
        return self.env in [Environment.STAGING, Environment.PRODUCTION]
    
    @property
    def use_managed_database(self) -> bool:
        return self.env == Environment.PRODUCTION
    
    @property
    def enable_billing(self) -> bool:
        return self.env == Environment.PRODUCTION

class Config:
    """Environment-based configuration"""
    def __init__(self):
        self.env = Environment(os.getenv('FLASK_ENV', 'development'))
        self.feature_flags = FeatureFlags(self.env)
        
    def get_config(self) -> Dict[str, Any]:
        base_config = {
            'SECRET_KEY': os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
            'JWT_EXPIRATION_DELTA': 3600,
            'BCRYPT_LOG_ROUNDS': 12 if self.env == Environment.PRODUCTION else 4,
        }
        
        if self.env == Environment.DEVELOPMENT:
            return {**base_config, **self._development_config()}
        elif self.env == Environment.STAGING:
            return {**base_config, **self._staging_config()}
        else:
            return {**base_config, **self._production_config()}
    
    def _development_config(self) -> Dict[str, Any]:
        return {
            'DEBUG': True,
            'MONGODB_URI': 'mongodb://localhost:27017/product_auth_dev',
            'HSM_ENDPOINT': None,  # Use mock HSM
            'STORAGE_TYPE': 'local',
            'STORAGE_PATH': './uploads',
            'EMAIL_BACKEND': 'smtp',
            'SMTP_HOST': 'smtp.gmail.com',
            'SMTP_PORT': 587,
            'BLOCKCHAIN_NETWORK': 'local',
            'GANACHE_URL': 'http://localhost:8545',
            'RATE_LIMIT_BACKEND': 'memory'
        }
    
    def _staging_config(self) -> Dict[str, Any]:
        return {
            'DEBUG': False,
            'MONGODB_URI': os.getenv('MONGODB_URI', 'mongodb://localhost:27017/product_auth_staging'),
            'HSM_ENDPOINT': None,  # Still mock for staging
            'STORAGE_TYPE': 's3',
            'S3_BUCKET': os.getenv('S3_BUCKET'),
            'EMAIL_BACKEND': 'ses',
            'BLOCKCHAIN_NETWORK': 'testnet',
            'RATE_LIMIT_BACKEND': 'redis'
        }
    
    def _production_config(self) -> Dict[str, Any]:
        return {
            'DEBUG': False,
            'MONGODB_URI': os.getenv('MONGODB_URI'),
            'HSM_ENDPOINT': os.getenv('AWS_CLOUDHSM_ENDPOINT'),
            'HSM_USER': os.getenv('HSM_USER'),
            'HSM_PASSWORD': os.getenv('HSM_PASSWORD'),
            'STORAGE_TYPE': 's3',
            'S3_BUCKET': os.getenv('S3_BUCKET'),
            'EMAIL_BACKEND': 'ses',
            'BLOCKCHAIN_NETWORK': 'mainnet',
            'RATE_LIMIT_BACKEND': 'redis',
            'VPC_ID': os.getenv('VPC_ID'),
            'SECURITY_GROUP_ID': os.getenv('SECURITY_GROUP_ID')
        }


# services/multi_tenant_service.py
from typing import Dict, Any, Optional, Set
from datetime import datetime, timedelta
import threading
import logging
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class MockVPCService:
    """Mock VPC service that simulates AWS VPC isolation locally"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vpc_enabled = config.get('VPC_ID') is not None
        self.security_groups = self._initialize_security_groups()
        self.subnets = self._initialize_subnets()
    
    def _initialize_security_groups(self) -> Dict[str, Dict[str, Any]]:
        """Initialize mock security groups"""
        return {
            'manufacturer-sg': {
                'rules': [
                    {'protocol': 'https', 'port': 443, 'source': '0.0.0.0/0'},
                    {'protocol': 'http', 'port': 80, 'source': '0.0.0.0/0'}
                ],
                'description': 'Security group for manufacturer endpoints'
            },
            'admin-sg': {
                'rules': [
                    {'protocol': 'https', 'port': 443, 'source': 'admin-subnet'},
                    {'protocol': 'ssh', 'port': 22, 'source': 'admin-subnet'}
                ],
                'description': 'Security group for admin access'
            }
        }
    
    def _initialize_subnets(self) -> Dict[str, Dict[str, Any]]:
        """Initialize mock subnets"""
        return {
            'public-subnet': {
                'cidr': '10.0.1.0/24',
                'type': 'public',
                'services': ['web', 'api']
            },
            'private-subnet': {
                'cidr': '10.0.2.0/24',
                'type': 'private',
                'services': ['database', 'hsm']
            },
            'admin-subnet': {
                'cidr': '10.0.3.0/24',
                'type': 'private',
                'services': ['admin']
            }
        }
    
    def check_security_group_access(self, manufacturer_id: str, 
                                   source_ip: str, protocol: str, port: int) -> bool:
        """Check if access is allowed by security groups"""
        if not self.vpc_enabled:
            return True  # Allow all access in development
        
        # In production, this would check real AWS security groups
        # For mock, we'll simulate basic checks
        if protocol == 'https' and port == 443:
            return True
        if protocol == 'http' and port == 80:
            return True
        
        logger.warning(f"Access denied for {source_ip}:{port} ({protocol})")
        return False
    
    def get_subnet_for_service(self, service: str) -> str:
        """Get appropriate subnet for a service"""
        for subnet_name, subnet_config in self.subnets.items():
            if service in subnet_config['services']:
                return subnet_name
        return 'public-subnet'  # Default subnet

class RateLimitService:
    """Memory-based rate limiting per manufacturer"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rate_limits = defaultdict(lambda: deque())
        self.lock = threading.Lock()
        self.default_limit = 1000  # requests per hour
        self.window_size = 3600  # 1 hour in seconds
    
    def check_rate_limit(self, manufacturer_id: str, 
                        limit: Optional[int] = None) -> Dict[str, Any]:
        """Check if manufacturer is within rate limits"""
        current_time = datetime.utcnow()
        limit = limit or self.default_limit
        
        with self.lock:
            requests = self.rate_limits[manufacturer_id]
            
            # Remove old requests outside the window
            cutoff_time = current_time - timedelta(seconds=self.window_size)
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Check if within limit
            if len(requests) >= limit:
                return {
                    'allowed': False,
                    'limit': limit,
                    'remaining': 0,
                    'reset_time': (requests[0] + timedelta(seconds=self.window_size)).isoformat(),
                    'retry_after': int((requests[0] + timedelta(seconds=self.window_size) - current_time).total_seconds())
                }
            
            # Add current request
            requests.append(current_time)
            
            return {
                'allowed': True,
                'limit': limit,
                'remaining': limit - len(requests),
                'reset_time': (current_time + timedelta(seconds=self.window_size)).isoformat()
            }
    
    def get_manufacturer_stats(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get rate limiting statistics for manufacturer"""
        with self.lock:
            requests = self.rate_limits[manufacturer_id]
            current_time = datetime.utcnow()
            
            # Count requests in different time windows
            last_hour = sum(1 for req_time in requests 
                           if req_time > current_time - timedelta(hours=1))
            last_day = sum(1 for req_time in requests 
                          if req_time > current_time - timedelta(days=1))
            
            return {
                'requests_last_hour': last_hour,
                'requests_last_day': last_day,
                'total_requests': len(requests)
            }

class MultiTenantService:
    """Main multi-tenant service orchestrator"""
    
    def __init__(self, config: Dict[str, Any], db_manager):
        self.config = config
        self.db_manager = db_manager
        self.vpc_service = MockVPCService(config)
        self.rate_limit_service = RateLimitService(config)
    
    def validate_tenant_access(self, manufacturer_id: str, 
                              source_ip: str, endpoint: str) -> Dict[str, Any]:
        """Validate tenant access with VPC and rate limiting"""
        # Check if manufacturer exists
        manufacturer = self.db_manager.get_manufacturer_by_id(manufacturer_id)
        if not manufacturer:
            return {'allowed': False, 'reason': 'Invalid manufacturer ID'}
        
        # Check VPC security groups
        if not self.vpc_service.check_security_group_access(
            manufacturer_id, source_ip, 'https', 443):
            return {'allowed': False, 'reason': 'VPC security group denied'}
        
        # Check rate limits
        manufacturer_config = self.db_manager.get_manufacturer_config(manufacturer_id)
        rate_limit_result = self.rate_limit_service.check_rate_limit(
            manufacturer_id, manufacturer_config.get('rate_limit'))
        
        if not rate_limit_result['allowed']:
            return {
                'allowed': False, 
                'reason': 'Rate limit exceeded',
                'rate_limit_info': rate_limit_result
            }
        
        return {
            'allowed': True,
            'manufacturer_config': manufacturer_config,
            'rate_limit_info': rate_limit_result
        }
    
    def get_tenant_isolation_info(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get information about tenant isolation setup"""
        manufacturer = self.db_manager.get_manufacturer_by_id(manufacturer_id)
        if not manufacturer:
            raise ValueError(f"Manufacturer {manufacturer_id} not found")
        
        return {
            'manufacturer_id': manufacturer_id,
            'database_prefix': manufacturer_id,
            'vpc_enabled': self.config.get('VPC_ID') is not None,
            'subnet': self.vpc_service.get_subnet_for_service('api'),
            'security_group': 'manufacturer-sg',
            'rate_limiting': {
                'enabled': True,
                'backend': self.config.get('RATE_LIMIT_BACKEND', 'memory'),
                'stats': self.rate_limit_service.get_manufacturer_stats(manufacturer_id)
            },
            'features_enabled': manufacturer.get('features_enabled', []),
            'billing_tier': manufacturer.get('billing_tier', 'basic')
        }

# Import required modules for datetime
from datetime import datetime