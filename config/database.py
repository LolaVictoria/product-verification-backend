import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import logging

logger = logging.getLogger(__name__)

_db_connection = None
class DatabaseConfig:
    def get_db_connection():
        """Get database connection with connection pooling"""
        global _db_connection
        
        if _db_connection is None:
            try:
                connection_string = os.getenv('MONGODB_URI')
                if not connection_string:
                    raise ValueError("MONGODB_URI environment variable not set")
                
                client = MongoClient(
                    connection_string,
                    maxPoolSize=50,
                    minPoolSize=10,
                    maxIdleTimeMS=30000,
                    serverSelectionTimeoutMS=300000
                )
                
                # Test connection
                client.admin.command('ping')
                
                db_name = os.getenv('DATABASE_NAME', 'verification_system')
                _db_connection = client[db_name]
                
                logger.info(f"Connected to database: {db_name}")
                
            except ConnectionFailure as e:
                logger.error(f"Database connection failed: {e}")
                raise
            except Exception as e:
                logger.error(f"Database setup error: {e}")
                raise
        
        return _db_connection

    def close_db_connection():
        """Close database connection"""
        global _db_connection
        if _db_connection:
            _db_connection.client.close()
            _db_connection = None

    def init_db():
        """Initialize database connection (for compatibility with app.py)"""
        return DatabaseConfig.get_db_connection()
database_config = DatabaseConfig()

# # config/settings.py
# import os
# from datetime import timedelta

# class Config:
#     """Base configuration"""
#     SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
#     JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
#     JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
#     # Database
#     MONGODB_URI = os.getenv('MONGODB_CONNECTION_STRING')
#     DATABASE_NAME = os.getenv('DATABASE_NAME', 'verification_system')
    
#     # Blockchain
#     BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL')
#     CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
#     CHAIN_ID = int(os.getenv('CHAIN_ID', '11155111'))
#     WALLET_ADDRESS = os.getenv('WALLET_ADDRESS')
    
#     # API Settings
#     API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100 per minute')
#     MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    
#     # Email (if needed)
#     SMTP_SERVER = os.getenv('SMTP_SERVER')
#     SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
#     SMTP_USERNAME = os.getenv('SMTP_USERNAME')
#     SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    
#     # CORS
#     CORS_ORIGINS = [
#         'http://localhost:3000',
#         'http://localhost:5173',
#         'https://blockchain-verification-esup.vercel.app'
#     ]

# class DevelopmentConfig(Config):
#     """Development configuration"""
#     DEBUG = True
#     TESTING = False

# class ProductionConfig(Config):
#     """Production configuration"""
#     DEBUG = False
#     TESTING = False
    
#     # More restrictive settings for production
#     JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
#     API_RATE_LIMIT = '50 per minute'

# class TestingConfig(Config):
#     """Testing configuration"""
#     TESTING = True
#     DATABASE_NAME = 'test_verification_system'

# # Get config based on environment
# config = {
#     'development': DevelopmentConfig,
#     'production': ProductionConfig,
#     'testing': TestingConfig,
#     'default': DevelopmentConfig
# }

# def get_config():
#     """Get configuration based on environment"""
#     env = os.getenv('FLASK_ENV', 'development')
#     return config.get(env, config['default'])

# config/blockchain.py
# import os
# from web3 import Web3
# import json
# import logging

# logger = logging.getLogger(__name__)

# class BlockchainConfig:
#     """Blockchain configuration and connection management"""
    
#     def __init__(self):
#         self.rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
#         self.contract_address = os.getenv('CONTRACT_ADDRESS')
#         self.chain_id = int(os.getenv('CHAIN_ID', '11155111'))
#         self.wallet_address = os.getenv('WALLET_ADDRESS')
#         self.private_key = os.getenv('PRIVATE_KEY')  # Be very careful with this
        
#         self.w3 = None
#         self.contract = None
        
#         self._initialize_web3()
#         self._load_contract()
    
#     def _initialize_web3(self):
#         """Initialize Web3 connection"""
#         if not self.rpc_url:
#             logger.warning("No blockchain RPC URL provided")
#             return
        
#         try:
#             self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
#             # Test connection
#             if self.w3.is_connected():
#                 logger.info(f"Connected to blockchain network (Chain ID: {self.chain_id})")
#             else:
#                 logger.error("Failed to connect to blockchain network")
                
#         except Exception as e:
#             logger.error(f"Blockchain connection error: {e}")
    
#     def _load_contract(self):
#         """Load smart contract"""
#         if not self.w3 or not self.contract_address:
#             return
        
#         try:
#             # Load contract ABI
#             abi_path = os.getenv('CONTRACT_ABI_PATH', 'contracts/abi/VerificationContract.json')
            
#             if os.path.exists(abi_path):
#                 with open(abi_path, 'r') as f:
#                     contract_abi = json.load(f)
                
#                 self.contract = self.w3.eth.contract(
#                     address=self.contract_address,
#                     abi=contract_abi
#                 )
#                 logger.info(f"Contract loaded: {self.contract_address}")
#             else:
#                 logger.warning(f"Contract ABI file not found: {abi_path}")
                
#         except Exception as e:
#             logger.error(f"Contract loading error: {e}")
    
#     def is_connected(self):
#         """Check if blockchain connection is active"""
#         return self.w3 and self.w3.is_connected()
    
#     def get_web3(self):
#         """Get Web3 instance"""
#         return self.w3
    
#     def get_contract(self):
#         """Get contract instance"""
#         return self.contract

# # Global blockchain instance
# blockchain_config = BlockchainConfig()