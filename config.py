import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET', 'fallback-jwt-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Database Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    
    # Blockchain Configuration
    WEB3_PROVIDER = os.getenv('PROVIDER_URL', 'http://127.0.0.1:7545')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '0x...')
    CONTRACT_ABI_PATH = os.getenv('CONTRACT_ABI_PATH', 'contract/contract_abi.json')
    
    # Account Configuration
    ACCOUNT_ADDRESS = os.getenv('ACCOUNT_ADDRESS')
    PRIVATE_KEY = os.getenv('PRIVATE_KEY')
    
    # API Keys
    ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
    
    # Rate Limiting
    RATE_LIMIT = os.getenv('RATE_LIMIT', '100/hour')
    
    # Flask Secret Key
    SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
     
     #Admin credentials
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@company.com')
    ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
    # Admin Credentials
    ADMIN_EMAIL='vickydamy@gmail.com'
    # Generate this hash using: python generate_password_hash.py
    ADMIN_PASSWORD_HASH='pbkdf2:sha256:150000$abc123$def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
    # JWT settings
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 8))
    
    # Blockchain settings (for future use)
    BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
    ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY')
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    # Override with more secure settings for production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  # Shorter expiry in production

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    MONGO_URI = os.getenv('TEST_MONGO_URI', 'mongodb://localhost:27017/test_product_auth_db')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}