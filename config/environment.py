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

