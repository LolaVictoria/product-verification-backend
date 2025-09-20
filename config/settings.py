# import os
# from datetime import timedelta

# class Config:
#     """Base configuration"""
#     SECRET_KEY = os.getenv('SECRET_KEY')
    
#     # Database
#     MONGODB_URI = os.getenv('MONGODB_URI')
    
#     # JWT
#     JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
#     JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
#     # Blockchain
#     BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL')
#     CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
#     CHAIN_ID = os.getenv('CHAIN_ID')
    
#     # API Settings
#     API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100/hour')
#     MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
#     # CORS
#     CORS_ORIGINS = [
#         'http://localhost:3000',
#         'http://localhost:5173',
#         'https://blockchain-verification-esup.vercel.app'
#     ]
    
#     # Email (if you add email functionality)
#     MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
#     MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
#     MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
#     MAIL_USERNAME = os.getenv('MAIL_USERNAME')
#     MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    
#     # Webhook Settings
#     WEBHOOK_TIMEOUT = int(os.getenv('WEBHOOK_TIMEOUT', '30'))
#     WEBHOOK_RETRIES = int(os.getenv('WEBHOOK_RETRIES', '3'))

# class DevelopmentConfig(Config):
#     """Development configuration"""
#     DEBUG = True
#     FLASK_ENV = 'development'
    
#     # More verbose logging in development
#     LOG_LEVEL = 'DEBUG'
    
#     # Allow insecure operations in development
#     TESTING = False

# class ProductionConfig(Config):
#     """Production configuration"""
#     DEBUG = False
#     FLASK_ENV = 'production'
    
#     # Security settings for production
#     SESSION_COOKIE_SECURE = True
#     SESSION_COOKIE_HTTPONLY = True
#     SESSION_COOKIE_SAMESITE = 'Lax'
    
#     # Logging
#     LOG_LEVEL = 'INFO'
    
#     # Rate limiting - stricter in production
#     API_RATE_LIMIT = '50/hour'

# class TestingConfig(Config):
#     """Testing configuration"""
#     TESTING = True
#     DEBUG = True
    
#     # Use in-memory database for testing
#     MONGODB_URI = 'mongodb://localhost:27017/blockchain_verification_test'
    
#     # Disable CSRF for testing
#     WTF_CSRF_ENABLED = False

# # Get config based on environment
# def get_config():
#     """Get configuration based on FLASK_ENV environment variable"""
#     env = os.getenv('FLASK_ENV', 'development').lower()
    
#     config_map = {
#         'development': DevelopmentConfig,
#         'production': ProductionConfig,
#         'testing': TestingConfig
#     }
    
#     return config_map.get(env, DevelopmentConfig)

import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    # Database
    MONGODB_URI = os.getenv('MONGODB_URI')
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'product_verification')
    
    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY') or os.getenv('SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Blockchain
    BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
    CHAIN_ID = int(os.getenv('CHAIN_ID', '11155111'))
    PRIVATE_KEY = os.getenv('PRIVATE_KEY')
    
    # API Settings
    API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100/hour')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # CORS
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5173',
        'https://blockchain-verification-esup.vercel.app'
    ]
    
    # Email Configuration
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
    SENDER_EMAIL = os.getenv('SENDER_EMAIL')
    SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
    
    # Webhook Settings
    WEBHOOK_TIMEOUT = int(os.getenv('WEBHOOK_TIMEOUT', '30'))
    WEBHOOK_RETRIES = int(os.getenv('WEBHOOK_RETRIES', '3'))
    
    # Security Settings
    BCRYPT_LOG_ROUNDS = 12
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # File Upload Settings
    ALLOWED_EXTENSIONS = {
        'images': ['jpg', 'jpeg', 'png', 'gif'],
        'documents': ['pdf', 'doc', 'docx'],
        'data': ['csv', 'json', 'xlsx']
    }
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'logs/app.log'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    FLASK_ENV = 'development'
    
    # More verbose logging in development
    LOG_LEVEL = 'DEBUG'
    
    # Less strict security for development
    BCRYPT_LOG_ROUNDS = 4
    SESSION_COOKIE_SECURE = False
    
    # Allow testing without HTTPS
    JWT_COOKIE_SECURE = False
    
    # Development database
    if not Config.MONGODB_URI:
        MONGODB_URI = 'mongodb://localhost:27017/product_verification_dev'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    FLASK_ENV = 'production'
    
    # Security settings for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Logging
    LOG_LEVEL = 'WARNING'
    
    # Rate limiting - stricter in production
    API_RATE_LIMIT = '50/hour'
    
    # Shorter JWT expiration in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory or test database
    MONGODB_URI = 'mongodb://localhost:27017/product_verification_test'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Fast hashing for tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Short token expiration for tests
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)

def get_config():
    """Get configuration based on FLASK_ENV environment variable"""
    env = os.getenv('FLASK_ENV', 'development').lower()
    
    config_map = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    return config_map.get(env, DevelopmentConfig)

# Application settings
class AppSettings:
    """Application-specific settings"""
    
    # Verification settings
    VERIFICATION_CACHE_TTL = 300  # 5 minutes
    MAX_BATCH_VERIFICATION_SIZE = 100
    
    # Analytics settings
    ANALYTICS_RETENTION_DAYS = 365
    DEFAULT_TIME_RANGE = '7d'
    
    # Notification settings
    EMAIL_RATE_LIMIT = 100  # emails per hour
    WEBHOOK_RATE_LIMIT = 1000  # webhooks per hour
    
    # Security settings
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    PASSWORD_MIN_LENGTH = 8
    
    # API settings
    API_VERSION = 'v1'
    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 100
    
    # File upload settings
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_MIME_TYPES = [
        'image/jpeg', 'image/png', 'image/gif',
        'application/pdf', 'text/csv', 'application/json'
    ]
    
    # Blockchain settings
    GAS_LIMIT = 300000
    GAS_PRICE_GWEI = 20
    CONFIRMATION_BLOCKS = 3
    
    @classmethod
    def get_setting(cls, key: str, default=None):
        """Get a setting value with fallback to default"""
        return getattr(cls, key, default)

# Export current config
current_config = get_config()
app_settings = AppSettings()