# helper_functions.py
from pymongo import MongoClient
from bson import ObjectId  # Use pymongo's bson instead of separate package
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3
import json
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Fix datetime deprecation warnings
def get_current_utc():
    return datetime.now(timezone.utc)

# Database connection
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client['product_verification']

# Load the actual ABI (try file first, then hardcoded)
users_collection = db['users']
products_collection = db['products']
api_keys_collection = db['api_keys']
api_usage_collection = db['api_usage']

# Blockchain configuration
BLOCKCHAIN_RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL', 'http://localhost:8545')
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '0x1234567890123456789012345678901234567890')
PRIVATE_KEY = os.getenv('PRIVATE_KEY', 'your-private-key-here')

# Load contract ABI from file or use the hardcoded version
def load_contract_abi():
    try:
        # Try to load from contract_abi.json file first
        with open('contract_abi.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to hardcoded ABI
        return CONTRACT_ABI_HARDCODED

CONTRACT_ABI_HARDCODED = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "InvalidSerialNumber",
        "type": "error"
    },
    {
        "inputs": [],
        "name": "ProductAlreadyExists",
        "type": "error"
    },
    {
        "inputs": [],
        "name": "UnauthorizedAccess",
        "type": "error"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "address",
                "name": "manufacturer",
                "type": "address"
            }
        ],
        "name": "ManufacturerAuthorized",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "string",
                "name": "serialNumber",
                "type": "string"
            },
            {
                "indexed": True,
                "internalType": "address",
                "name": "manufacturer",
                "type": "address"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "name",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "name": "ProductRegistered",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "_manufacturer",
                "type": "address"
            }
        ],
        "name": "authorizeManufacturer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "name": "authorizedManufacturers",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_serialNumber",
                "type": "string"
            }
        ],
        "name": "isProductVerified",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_serialNumber",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_name",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_category",
                "type": "string"
            }
        ],
        "name": "registerProduct",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_serialNumber",
                "type": "string"
            }
        ],
        "name": "verifyProduct",
        "outputs": [
            {
                "internalType": "bool",
                "name": "verified",
                "type": "bool"
            },
            {
                "internalType": "address",
                "name": "manufacturer",
                "type": "address"
            },
            {
                "internalType": "string",
                "name": "name",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "category",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]
CONTRACT_ABI = load_contract_abi()

class BlockchainService:
    def __init__(self):
        try:
            self.web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
            self.contract = self.web3.eth.contract(
                address=CONTRACT_ADDRESS,
                abi=CONTRACT_ABI
            )
            self.account = self.web3.eth.account.from_key(PRIVATE_KEY) if PRIVATE_KEY != 'your-private-key-here' else None
            self.connected = self.web3.is_connected()
        except Exception as e:
            print(f"Blockchain connection failed: {e}")
            self.connected = False
    
    def register_product_on_blockchain(self, serial_number, product_name, category, manufacturer_address):
        """Register a product on the blockchain"""
        if not self.connected or not self.account:
            print("Blockchain not connected or no account configured")
            return None
            
        try:
            # Build transaction for registerProduct function
            transaction = self.contract.functions.registerProduct(
                serial_number,
                product_name,
                category
            ).build_transaction({
                'from': self.account.address,
                'gas': 200000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': receipt['transactionHash'].hex(),
                'block_number': receipt['blockNumber']
            }
            
        except Exception as e:
            print(f"Blockchain registration error: {e}")
            return {'success': False, 'error': str(e)}
    
    def verify_product_on_blockchain(self, serial_number):
        """Verify a product exists on the blockchain using verifyProduct function"""
        if not self.connected:
            return False
            
        try:
            # Call verifyProduct function which returns (verified, manufacturer, name, category, timestamp)
            result = self.contract.functions.verifyProduct(serial_number).call()
            return result[0]  # Returns the 'verified' boolean
        except Exception as e:
            print(f"Blockchain verification error: {e}")
            return False
    
    def is_product_verified_simple(self, serial_number):
        """Simple check using isProductVerified function"""
        if not self.connected:
            return False
            
        try:
            # Call isProductVerified function which returns just a boolean
            result = self.contract.functions.isProductVerified(serial_number).call()
            return result
        except Exception as e:
            print(f"Blockchain simple verification error: {e}")
            return False
    
    def get_product_details_blockchain(self, serial_number):
        """Get full product details from blockchain"""
        if not self.connected:
            return None
            
        try:
            # Call verifyProduct to get full details
            result = self.contract.functions.verifyProduct(serial_number).call()
            
            if result[0]:  # if verified is True
                return {
                    'verified': result[0],
                    'manufacturer': result[1],
                    'name': result[2],
                    'category': result[3],
                    'timestamp': result[4]
                }
            return None
            
        except Exception as e:
            print(f"Error getting product details: {e}")
            return None
    
    def authorize_manufacturer_on_blockchain(self, manufacturer_address):
        """Authorize a manufacturer on the blockchain (admin function)"""
        if not self.connected or not self.account:
            return False
            
        try:
            # Build transaction for authorizeManufacturer function
            transaction = self.contract.functions.authorizeManufacturer(
                manufacturer_address
            ).build_transaction({
                'from': self.account.address,
                'gas': 100000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            return receipt['status'] == 1  # 1 means success
            
        except Exception as e:
            print(f"Manufacturer authorization error: {e}")
            return False
    
    def is_manufacturer_authorized(self, manufacturer_address):
        """Check if a manufacturer is authorized"""
        if not self.connected:
            return False
            
        try:
            result = self.contract.functions.authorizedManufacturers(manufacturer_address).call()
            return result
        except Exception as e:
            print(f"Error checking manufacturer authorization: {e}")
            return False

# Initialize blockchain service
blockchain_service = BlockchainService()

def verify_on_blockchain(serial_number):
    """Wrapper function for blockchain verification"""
    return blockchain_service.verify_product_on_blockchain(serial_number)

def register_product_blockchain(serial_number, product_name, category, manufacturer_address):
    """Wrapper function for blockchain product registration"""
    return blockchain_service.register_product_on_blockchain(
        serial_number, product_name, category, manufacturer_address
    )

def verify_manufacturer_on_blockchain(manufacturer_address):
    """Wrapper function for manufacturer authorization on blockchain"""
    return blockchain_service.authorize_manufacturer_on_blockchain(manufacturer_address)

def check_manufacturer_authorization(manufacturer_address):
    """Check if manufacturer is authorized on blockchain"""
    return blockchain_service.is_manufacturer_authorized(manufacturer_address)

def get_blockchain_product_details(serial_number):
    """Get detailed product info from blockchain"""
    return blockchain_service.get_product_details_blockchain(serial_number)

def hash_password(password):
    """Hash a password for storing"""
    return generate_password_hash(password)

def verify_password(password_hash, password):
    """Verify a password against its hash"""
    return check_password_hash(password_hash, password)

def get_user_by_email(email):
    """Get user by email from database"""
    return users_collection.find_one({"email": email})

def get_user_by_id(user_id):
    """Get user by ID from database"""
    from bson import ObjectId
    return users_collection.find_one({"_id": ObjectId(user_id)})

def create_user(user_data):
    """Create a new user in database"""
    user_data['created_at'] = get_current_utc()
    user_data['updated_at'] = get_current_utc()
    result = users_collection.insert_one(user_data)
    return str(result.inserted_id)

def update_user_verification_status(user_id, status):
    """Update user verification status"""
    result = users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "verification_status": status,
                "updated_at": get_current_utc()
            }
        }
    )
    return result.modified_count > 0

def get_product_by_serial(serial_number):
    """Get product by serial number"""
    return products_collection.find_one({"serial_number": serial_number})

def create_product(product_data):
    """Create a new product in database"""
    product_data['registered_at'] = datetime.utcnow()
    result = products_collection.insert_one(product_data)
    return str(result.inserted_id)

def get_all_products():
    """Get all products from database"""
    return list(products_collection.find({}))

def get_products_by_manufacturer(manufacturer_id):
    """Get all products by a specific manufacturer"""
    from bson import ObjectId
    return list(products_collection.find({"manufacturer_id": ObjectId(manufacturer_id)}))

def get_pending_manufacturers():
    """Get all manufacturers with pending verification status"""
    return list(users_collection.find({
        "role": "manufacturer",
        "verification_status": "pending"
    }))

def generate_api_key():
    """Generate a unique API key"""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(32))

def create_api_key(user_id, label):
    """Create a new API key for a user"""
    api_key_data = {
        "user_id": ObjectId(user_id),
        "key": generate_api_key(),
        "label": label,
        "created_at": get_current_utc(),
        "revoked": False,
        "usage_count": 0
    }
    result = api_keys_collection.insert_one(api_key_data)
    return api_key_data["key"]

def get_api_keys_by_user(user_id):
    """Get all API keys for a user"""
    return list(api_keys_collection.find({
        "user_id": ObjectId(user_id),
        "revoked": False
    }))

def validate_api_key(api_key):
    """Validate an API key and return user info"""
    key_data = api_keys_collection.find_one({
        "key": api_key,
        "revoked": False
    })
    
    if not key_data:
        return None
    
    # Increment usage count
    api_keys_collection.update_one(
        {"_id": key_data["_id"]},
        {"$inc": {"usage_count": 1}}
    )
    
    # Log API usage
    log_api_usage(key_data["_id"], key_data["user_id"], "verify", "unknown")
    
    return key_data

def log_api_usage(api_key_id, user_id, endpoint, ip_address, response_status=200):
    """Log API usage"""
    usage_data = {
        "api_key_id": api_key_id,
        "user_id": user_id,
        "endpoint": endpoint,
        "ip_address": ip_address,
        "timestamp": get_current_utc(),
        "response_status": response_status
    }
    api_usage_collection.insert_one(usage_data)

def is_valid_wallet_address(address):
    """Validate Ethereum wallet address format"""
    import re
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))

def format_product_response(product):
    """Format product data for API response"""
    if not product:
        return None
    
    return {
        "serial_number": product.get("serial_number"),
        "name": product.get("name"),
        "category": product.get("category"),
        "manufacturer_name": product.get("manufacturer_name"),
        "price": product.get("price"),
        "image_url": product.get("image_url"),
        "blockchain_verified": product.get("blockchain_verified", False),
        "verified": product.get("verified", False),
        "registered_at": product.get("registered_at")
    }

def format_user_response(user):
    """Format user data for API response"""
    if not user:
        return None
    
    return {
        "id": str(user["_id"]),
        "email": user.get("email"),
        "role": user.get("role"),
        "wallet_address": user.get("wallet_address"),
        "verification_status": user.get("verification_status"),
        "created_at": user.get("created_at")
    }

# Error handling helpers
class ValidationError(Exception):
    pass

class AuthenticationError(Exception):
    pass

class BlockchainError(Exception):
    pass

def validate_required_fields(data, required_fields):
    """Validate that all required fields are present"""
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

def validate_product_data(data):
    """Validate product registration data"""
    required_fields = ["serial_number", "name", "category"]
    validate_required_fields(data, required_fields)
    
    # Check if product already exists
    existing_product = get_product_by_serial(data["serial_number"])
    if existing_product:
        raise ValidationError("Product with this serial number already exists")

def validate_user_registration(data):
    """Validate user registration data"""
    required_fields = ["email", "password", "role"]
    validate_required_fields(data, required_fields)
    
    # Check if user already exists
    existing_user = get_user_by_email(data["email"])
    if existing_user:
        raise ValidationError("User with this email already exists")
    
    # Validate wallet address for manufacturers
    if data["role"] == "manufacturer":
        if not data.get("wallet_address"):
            raise ValidationError("Wallet address is required for manufacturers")
        if not is_valid_wallet_address(data["wallet_address"]):
            raise ValidationError("Invalid wallet address format")

# Database initialization
def init_database():
    """Initialize database with indexes"""
    try:
        # Create indexes for better performance
        users_collection.create_index("email", unique=True)
        products_collection.create_index("serial_number", unique=True)
        api_keys_collection.create_index("key", unique=True)
        api_keys_collection.create_index("user_id")
        api_usage_collection.create_index("timestamp")
        
        print("Database indexes created successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Initialize database on import
init_database()