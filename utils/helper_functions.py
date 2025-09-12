# helper_functions.py - All helper functions
from pymongo import MongoClient
from datetime import datetime, timezone
import bcrypt
import secrets
import re
from bson import ObjectId
from web3 import Web3
import json
import os
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import hashlib
from datetime import datetime, timezone
from datetime import datetime, timedelta
from web3 import Web3
import os
from dotenv import load_dotenv



contract_abi_json = '''[
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "string",
        "name": "serialNumber",
        "type": "string"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "manufacturer",
        "type": "address"
      }
    ],
    "name": "DeviceRegistered",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "string",
        "name": "serialNumber",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "bool",
        "name": "isAuthentic",
        "type": "bool"
      }
    ],
    "name": "DeviceVerified",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "manufacturer",
        "type": "address"
      }
    ],
    "name": "ManufacturerAuthorized",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "manufacturer",
        "type": "address"
      }
    ],
    "name": "ManufacturerRevoked",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "manufacturer",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "companyName",
        "type": "string"
      }
    ],
    "name": "ManufacturerVerified",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "string",
        "name": "serialNumber",
        "type": "string"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "from",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "to",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "price",
        "type": "uint256"
      }
    ],
    "name": "OwnershipTransferred",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "admin",
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
        "internalType": "address[]",
        "name": "_manufacturers",
        "type": "address[]"
      }
    ],
    "name": "batchAuthorizeManufacturers",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "",
        "type": "string"
      }
    ],
    "name": "devices",
    "outputs": [
      {
        "internalType": "string",
        "name": "serialNumber",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "brand",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "model",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "deviceType",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "storageData",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "color",
        "type": "string"
      },
      {
        "internalType": "address",
        "name": "manufacturer",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "currentOwner",
        "type": "address"
      },
      {
        "internalType": "uint256",
        "name": "manufacturingDate",
        "type": "uint256"
      },
      {
        "internalType": "string",
        "name": "batchNumber",
        "type": "string"
      },
      {
        "internalType": "bool",
        "name": "isAuthentic",
        "type": "bool"
      },
      {
        "internalType": "uint256",
        "name": "registrationTime",
        "type": "uint256"
      },
      {
        "internalType": "string",
        "name": "specificationHash",
        "type": "string"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getAllAuthorizedManufacturers",
    "outputs": [
      {
        "internalType": "address[]",
        "name": "",
        "type": "address[]"
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
    "name": "getDeviceDetails",
    "outputs": [
      {
        "internalType": "string",
        "name": "brand",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "model",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "deviceType",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "storageData",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "color",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "manufacturerName",
        "type": "string"
      },
      {
        "internalType": "address",
        "name": "currentOwner",
        "type": "address"
      },
      {
        "internalType": "uint256",
        "name": "manufacturingDate",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_owner",
        "type": "address"
      }
    ],
    "name": "getOwnerDevices",
    "outputs": [
      {
        "internalType": "string[]",
        "name": "",
        "type": "string[]"
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
    "name": "getOwnershipHistory",
    "outputs": [
      {
        "internalType": "address[]",
        "name": "previousOwners",
        "type": "address[]"
      },
      {
        "internalType": "address[]",
        "name": "newOwners",
        "type": "address[]"
      },
      {
        "internalType": "uint256[]",
        "name": "transferDates",
        "type": "uint256[]"
      },
      {
        "internalType": "string[]",
        "name": "transferReasons",
        "type": "string[]"
      },
      {
        "internalType": "uint256[]",
        "name": "salePrices",
        "type": "uint256[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_manufacturer",
        "type": "address"
      }
    ],
    "name": "isManufacturerAuthorized",
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
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "manufacturerList",
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
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "name": "manufacturers",
    "outputs": [
      {
        "internalType": "string",
        "name": "companyName",
        "type": "string"
      },
      {
        "internalType": "address",
        "name": "walletAddress",
        "type": "address"
      },
      {
        "internalType": "bool",
        "name": "isVerified",
        "type": "bool"
      },
      {
        "internalType": "uint256",
        "name": "registrationTime",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      },
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "ownerDevices",
    "outputs": [
      {
        "internalType": "string",
        "name": "",
        "type": "string"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "",
        "type": "string"
      },
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "ownershipHistory",
    "outputs": [
      {
        "internalType": "address",
        "name": "previousOwner",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "newOwner",
        "type": "address"
      },
      {
        "internalType": "uint256",
        "name": "transferDate",
        "type": "uint256"
      },
      {
        "internalType": "string",
        "name": "transferReason",
        "type": "string"
      },
      {
        "internalType": "uint256",
        "name": "salePrice",
        "type": "uint256"
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
        "name": "_brand",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_model",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_deviceType",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_storage",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_color",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_batchNumber",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "_specHash",
        "type": "string"
      }
    ],
    "name": "registerDevice",
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
    "name": "revokeDeviceAuthenticity",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "_manufacturer",
        "type": "address"
      }
    ],
    "name": "revokeManufacturer",
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
    "name": "serialExists",
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
      },
      {
        "internalType": "address",
        "name": "_newOwner",
        "type": "address"
      },
      {
        "internalType": "string",
        "name": "_transferReason",
        "type": "string"
      },
      {
        "internalType": "uint256",
        "name": "_salePrice",
        "type": "uint256"
      }
    ],
    "name": "transferOwnership",
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
    "name": "verifiedManufacturers",
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
    "name": "verifyDevice",
    "outputs": [
      {
        "internalType": "bool",
        "name": "exists",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "isAuthentic",
        "type": "bool"
      },
      {
        "internalType": "string",
        "name": "brand",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "model",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "deviceType",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "manufacturerName",
        "type": "string"
      },
      {
        "internalType": "address",
        "name": "currentOwner",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string[]",
        "name": "_serialNumbers",
        "type": "string[]"
      }
    ],
    "name": "verifyMultipleDevices",
    "outputs": [
      {
        "internalType": "bool[]",
        "name": "exists",
        "type": "bool[]"
      },
      {
        "internalType": "bool[]",
        "name": "isAuthentic",
        "type": "bool[]"
      },
      {
        "internalType": "string[]",
        "name": "brands",
        "type": "string[]"
      },
      {
        "internalType": "string[]",
        "name": "models",
        "type": "string[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
]'''

# Load environment variables
load_dotenv()
contract_abi = json.loads(contract_abi_json)       
contract_address =  os.getenv('CONTRACT_ADDRESS')
RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL')
    
# Initialize Web3 in helper_functions
try:
    w3 = Web3(Web3.HTTPProvider(os.getenv('BLOCKCHAIN_RPC_URL')))
    if w3.is_connected():
        print("Web3 connected successfully in helper_functions")
    else:
        print("Web3 connection failed in helper_functions")
        w3 = None
except Exception as e:
    print(f"Web3 initialization error in helper_functions: {e}")
    w3 = None
    
# Custom Exceptions
class ValidationError(Exception):
    pass

class AuthenticationError(Exception):
    pass

class BlockchainError(Exception):
    pass

# Database connection
def get_db_connection():
    client = MongoClient(os.getenv('MONGODB_URI'))
    return client['product_verification']

# Utility Functions
def get_current_utc():
    return datetime.now(timezone.utc)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# Enhanced password verification with debugging
def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify password with debugging"""
    try:
        print(f"🔐 Verifying password...")
        print(f"🔐 Hash method detection...")
        
        # Check if it's bcrypt
        if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$') or stored_hash.startswith('$2y$'):
            print("🔐 Detected bcrypt hash")
            import bcrypt
            result = bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash.encode('utf-8'))
            print(f"🔐 bcrypt verification: {result}")
            return result
            
        # Check if it's pbkdf2 (Werkzeug style)
        elif stored_hash.startswith('pbkdf2:'):
            print("🔐 Detected pbkdf2 hash")
            from werkzeug.security import check_password_hash
            result = check_password_hash(stored_hash, provided_password)
            print(f"🔐 pbkdf2 verification: {result}")
            return result
            
        # Check if it's plain text (NOT recommended for production)
        elif len(stored_hash) < 50:  # Plain text is usually much shorter
            print("⚠️  WARNING: Possible plain text password detected!")
            result = stored_hash == provided_password
            print(f"🔐 Plain text verification: {result}")
            return result
            
        else:
            print(f"❌ Unknown hash format: {stored_hash[:20]}...")
            return False
            
    except Exception as e:
        print(f"❌ Password verification error: {e}")
        return False

def format_user_response(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("name"),
        "primary_email": user.get("primary_email") or user.get("emails[0]"),
        "emails": user.get("emails", [user.get("email")] if user.get("email") else []),
        "role": user["role"],
        "verification_status": user.get("verification_status"),
        "company_names": user.get("company_names", [user.get("company_name")] if user.get("company_name") else []),
        "current_company_name": user.get("current_company_name") or user.get("company_name"),
        "es": user.get("wallet_addresses", [user.get("wallet_address")] if user.get("wallet_address") else []),
        "primary_wallet": user.get("primary_wallet") or user.get("wallet_address"),
        "verified_wallets": user.get("verified_wallets", []),
        "created_at": user.get("created_at")
    }

def update_user(user_id, update_data):

    """Update user in database"""
    try:
        from bson import ObjectId
        
        # Convert string id to ObjectId if needed
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        # Remove any None values from update_data
        filtered_data = {k: v for k, v in update_data.items() if v is not None}
        db = get_db_connection()
        # Update the user document
        result = db.users.update_one(
            {"_id": user_id},
            {"$set": filtered_data}
        )
        
        if result.modified_count == 0:
            return None
        
        # Return the updated user
        updated_user = db.users.find_one({"_id": user_id})
        return updated_user
        
    except Exception as e:
        print(f"Error updating user: {e}")
        return None
def format_product_response(product):
    return {
        "id": str(product.get("_id", "")),
        "serial_number": product.get("serial_number"),
        "name": product.get("name") or f"{product.get('brand', '')} {product.get('model', '')}".strip(),
        "brand": product.get("brand"),
        "model": product.get("model"),
        "device_type": product.get("device_type"),
        "category": product.get("category") or product.get("device_type"),
        "storage_data": product.get("storage_data"),
        "color": product.get("color"),
        "batch_number": product.get("batch_number"),
        "manufacturer_name": product.get("manufacturer_name"),
        "manufacturer_wallet": product.get("manufacturer_wallet"),
        "current_owner": product.get("current_owner"),
        "price": product.get("price", 0),
        "registration_type": product.get("registration_type"),
        "blockchain_verified": product.get("registration_type") == "blockchain_confirmed",
        "verified": product.get("verified", False),
        "registered_at": product.get("registered_at") or product.get("created_at"),
        "transaction_hash": product.get("transaction_hash"),
        "block_number": product.get("block_number"),
        "specification_hash": product.get("specification_hash")
    }

# Validation Functions
def validate_user_registration(data):
    required_fields = ["email", "password", "role"]
    for field in required_fields:
        if not data.get(field):
            raise ValidationError(f"{field} is required")
    
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', data["email"]):
        raise ValidationError("Invalid email format")
    
    if len(data["password"]) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    
    if data["role"] not in ["customer", "manufacturer", "developer", "admin"]:
        raise ValidationError("Invalid role")
    
    # Manufacturer-specific validation
    if data["role"] == "manufacturer":
        if not data.get("wallet_address"):
            raise ValidationError("Wallet address is required for manufacturers")
        
        if not re.match(r'^0x[a-fA-F0-9]{40}$', data["wallet_address"]):
            raise ValidationError("Invalid Ethereum wallet address format")

def validate_product_data(data):
    required_fields = ["serial_number", "name", "category"]
    for field in required_fields:
        if not data.get(field):
            raise ValidationError(f"{field} is required")
    
    if len(data["serial_number"]) < 3:
        raise ValidationError("Serial number must be at least 3 characters long")
    
    valid_categories = ["Electronics", "Clothing", "Shoes", "Bags", "Accessories", "Home Appliances", "Automotive", "Other"]
    if data["category"] not in valid_categories:
        raise ValidationError("Invalid category")
    
    if data.get("price") and float(data["price"]) < 0:
        raise ValidationError("Price cannot be negative")

# Database Functions
def get_user_by_email(email):
    db = get_db_connection()
    return db.users.find_one({
        "$or": [
            {"primary_email": email},
            {"emails": email}
        ]
    })

def get_user_by_id(user_id):
    db = get_db_connection()
    try:
        return db.users.find_one({"_id": ObjectId(user_id)})
    except:
        return None

def create_user(user_data):
    db = get_db_connection()
    result = db.users.insert_one(user_data)
    return str(result.inserted_id)

def update_user_verification_status(user_id, status):
    db = get_db_connection()
    try:
        result = db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"verification_status": status, "updated_at": get_current_utc()}}
        )
        return result.modified_count > 0
    except:
        return False

def get_product_by_serial(serial_number):
    try:
        db = get_db_connection()
        return db.products.find_one({"serial_number": serial_number})
    except Exception as e:
        print(f"Error checking serial: {e}")
        return None

def create_product(product_data):
    db = get_db_connection()
    result = db.products.insert_one(product_data)
    return str(result.inserted_id)

def get_all_products():
    db = get_db_connection()
    return list(db.products.find().sort("registered_at", -1))

def get_products_by_manufacturer(manufacturer_id):
    db = get_db_connection()
    try:
        return list(db.products.find({"manufacturer_id": manufacturer_id}).sort("registered_at", -1))
    except:
        return []

def get_pending_manufacturers():
    db = get_db_connection()
    return list(db.users.find({"role": "manufacturer", "verification_status": "pending"}))

def create_api_key(user_id, label):
    db = get_db_connection()
    api_key = secrets.token_urlsafe(32)
    
    api_key_data = {
        "user_id": user_id,
        "key": api_key,
        "label": label,
        "created_at": get_current_utc(),
        "usage_count": 0
    }
    
    db.api_keys.insert_one(api_key_data)
    return api_key

def get_api_keys_by_user(user_id):
    db = get_db_connection()
    return list(db.api_keys.find({"user_id": user_id}))

def validate_api_key(api_key):
    db = get_db_connection()
    key_data = db.api_keys.find_one({"key": api_key})
    if key_data:
        # Update usage count
        db.api_keys.update_one(
            {"_id": key_data["_id"]},
            {"$inc": {"usage_count": 1}}
        )
    return key_data

# Blockchain Service Class
class BlockchainService:
    def __init__(self):
        self.web3 = None
        self.contract = None
        self.account = None
        self.connected = False
        self.initialize_connection()
    
    def initialize_connection(self):
        try:
            # Initialize Web3 connection
            rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
            if not rpc_url:
                print("Warning: BLOCKCHAIN_RPC_URL not set")
                return
            
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
            
            if not self.web3.is_connected():
                print("Warning: Cannot connect to blockchain")
                return
            
            # Load contract
            contract_address = os.getenv('CONTRACT_ADDRESS')
            contract_abi = self.get_contract_abi()
            
            if contract_address and contract_abi:
                self.contract = self.web3.eth.contract(
                    address=contract_address,
                    abi=contract_abi
                )
            
            # Load account for transactions
            private_key = os.getenv('PRIVATE_KEY')
            if private_key:
                self.account = self.web3.eth.account.from_key(private_key)
            
            self.connected = True
            print("Blockchain connection established successfully")
            
        except Exception as e:
            print(f"Blockchain connection failed: {e}")
            self.connected = False
    
    def get_contract_abi(self):
        # Simplified ABI for the smart contract
        return [
            {
                "inputs": [{"name": "serialNumber", "type": "string"}],
                "name": "getProduct",
                "outputs": [
                    {"name": "manufacturer", "type": "address"},
                    {"name": "name", "type": "string"},
                    {"name": "category", "type": "string"},
                    {"name": "timestamp", "type": "uint256"},
                    {"name": "isVerified", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"name": "serialNumber", "type": "string"},
                    {"name": "name", "type": "string"},
                    {"name": "category", "type": "string"}
                ],
                "name": "registerProduct",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "manufacturer", "type": "address"}],
                "name": "authorizeManufacturer",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "manufacturer", "type": "address"}],
                "name": "isAuthorizedManufacturer",
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "serialNumber", "type": "string"}],
                "name": "isProductVerified",
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
    
    def is_product_verified_simple(serial_number):
        """Simple verification check"""
        if not self.connected or not self.contract:
            return False
        
        try:
            return self.contract.functions.isProductVerified(serial_number).call()
        except Exception as e:
            print(f"Blockchain verification error: {e}")
            return False
    
    def get_product_details_blockchain(self, serial_number):
        """Get detailed product information from blockchain"""
        if not self.connected or not self.contract:
            return None
        
        try:
            result = self.contract.functions.getProduct(serial_number).call()
            manufacturer, name, category, timestamp, is_verified = result
            
            if is_verified:
                return {
                    "manufacturer": manufacturer,
                    "name": name,
                    "category": category,
                    "timestamp": timestamp,
                    "is_verified": is_verified
                }
            return None
            
        except Exception as e:
            print(f"Blockchain product details error: {e}")
            return None
    
    def register_product_on_blockchain(self, serial_number, name, category, manufacturer_address):
        """Register a new product on blockchain"""
        if not self.connected or not self.contract or not self.account:
            raise BlockchainError("Blockchain not connected or account not configured")
        
        try:
            # Build transaction
            transaction = self.contract.functions.registerProduct(
                serial_number, name, category
            ).build_transaction({
                'from': self.account.address,
                'gas': 200000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
            })
            
            # Sign and send transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            return {
                "success": True,
                "tx_hash": receipt.transactionHash.hex(),
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed
            }
            
        except Exception as e:
            print(f"Blockchain registration error: {e}")
            raise BlockchainError(f"Failed to register product on blockchain: {str(e)}")
    
    def authorize_manufacturer_on_blockchain(self, manufacturer_address):
        """Authorize a manufacturer on blockchain"""
        if not self.connected or not self.contract or not self.account:
            return False
        
        try:
            transaction = self.contract.functions.authorizeManufacturer(
                manufacturer_address
            ).build_transaction({
                'from': self.account.address,
                'gas': 100000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
            })
            
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            return receipt.status == 1
            
        except Exception as e:
            print(f"Manufacturer authorization error: {e}")
            return False
    
    def is_manufacturer_authorized(self, manufacturer_address):
        """Check if manufacturer is authorized"""
        if not self.connected or not self.contract:
            return False
        
        try:
            return self.contract.functions.isAuthorizedManufacturer(manufacturer_address).call()
        except Exception as e:
            print(f"Manufacturer authorization check error: {e}")
            return False

# Initialize blockchain service
blockchain_service = BlockchainService()

# Blockchain wrapper functions for backward compatibility
def verify_on_blockchain(serial_number):
    return blockchain_service.is_product_verified_simple(serial_number)

def register_product_blockchain(serial_number, name, category, manufacturer_address):
    return blockchain_service.register_product_on_blockchain(serial_number, name, category, manufacturer_address)

def verify_manufacturer_on_blockchain(manufacturer_address):
    return blockchain_service.authorize_manufacturer_on_blockchain(manufacturer_address)

def check_manufacturer_authorization(manufacturer_address):
    return blockchain_service.is_manufacturer_authorized(manufacturer_address)

def get_blockchain_product_details(serial_number):
    """Enhanced function to get comprehensive blockchain product details"""
    if not blockchain_service.connected:
        return None
    
    details = blockchain_service.get_product_details_blockchain(serial_number)
    
    if details:
        # Get additional blockchain info
        try:
            # Get the latest block to calculate relative timing
            latest_block = blockchain_service.web3.eth.get_block('latest')
            
            details.update({
                "block_number": latest_block.number,  # This would be the actual block in real implementation
                "network": "Ethereum" if blockchain_service.web3.net.version == '1' else "Testnet",
                "confirmed": True
            })
        except:
            pass
    
    return details


# Enhanced verification function that falls back to mock if blockchain unavailable
def get_blockchain_product_details_enhanced(serial_number):
    """Try real blockchain first, fall back to mock for development"""
    
    # Try real blockchain first
    if blockchain_service.connected:
        return get_blockchain_product_details(serial_number)
   
# Override the original function for development
get_blockchain_product_details = get_blockchain_product_details_enhanced


#edit profile
def get_primary_email(user):
    # Handle new structure
    if user.get('primary_email'):
        return user['primary_email']
    
    # Handle array structure
    emails = user.get('emails', [])
    if isinstance(emails, list) and emails:
        for email in emails:
            if isinstance(email, dict) and email.get('is_primary'):
                return email['email']
        # Return first email if no primary found
        first_email = emails[0]
        return first_email['email'] if isinstance(first_email, dict) else first_email
    
    # Fallback to old structure
    return user.get('email')

def get_primary_wallet(user):
    # Handle new structure
    if user.get('primary_wallet'):
        return user['primary_wallet']
    
    # Handle array structure  
    wallets = user.get('wallet_addresses', [])
    if isinstance(wallets, list) and wallets:
        for wallet in wallets:
            if isinstance(wallet, dict) and wallet.get('is_primary'):
                return wallet
        # Return first wallet if no primary found
        first_wallet = wallets[0]
        return first_wallet if isinstance(first_wallet, dict) else {'address': first_wallet}
    
    # Fallback to old structure
    old_wallet = user.get('wallet_address')
    return {'address': old_wallet} if old_wallet else None

def get_verified_wallets(user):
    # Handle new structure
    if user.get('verified_wallets'):
        return user['verified_wallets']
    
    # Handle array structure
    wallets = user.get('wallet_addresses', [])
    if isinstance(wallets, list):
        verified = [w for w in wallets if isinstance(w, dict) and w.get('status') == 'verified']
        if verified:
            return verified
    
    # Fallback to old structure - if wallet exists and user is verified, consider it verified
    old_wallet = user.get('wallet_address')
    if old_wallet and user.get('verification_status') == 'verified':
        return [{'address': old_wallet, 'status': 'verified'}]
    
    return []

def get_current_company_name(user):
    # Handle new structure
    if user.get('current_company_name'):
        return user['current_company_name']
    
    # Handle array structure
    names = user.get('company_names', [])
    if isinstance(names, list) and names:
        for name_entry in names:
            if isinstance(name_entry, dict) and name_entry.get('is_current'):
                return name_entry['name']
        # Return first name if no current found
        first_name = names[0]
        return first_name['name'] if isinstance(first_name, dict) else first_name
    
    # Fallback to old structure
    return user.get('company_name')

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_wallet_address(address):
    # Basic Ethereum address validation
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return re.match(pattern, address) is not None

def email_exists_globally(email):
    db = get_db_connection()
    return db.users.find_one({"emails.email": email}) is not None

def wallet_exists_globally(wallet):
    db = get_db_connection()
    return db.users.find_one({"wallet_addresses.address": wallet}) is not None



def generate_verification_token(length=32):
    """Generate a secure random token for email verification"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def send_email_verification(email, token):
    """Send email verification link to user"""
    try:
        # Email configuration (use environment variables in production)
        SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
        SENDER_EMAIL = os.getenv('SENDER_EMAIL')
        SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')  # Use app password
        BASE_URL = os.getenv('BASE_URL', 'https://yourapp.com')
        
        if not SENDER_EMAIL or not SENDER_PASSWORD:
            print("Email credentials not configured")
            return False
        
        # Create verification link
        verification_link = f"{BASE_URL}/verify-email/{token}"
        
        # Email content
        subject = "Verify Your Email Address"
        body = f"""
        <html>
        <body>
            <h2>Email Verification Required</h2>
            <p>Thank you for adding this email to your account.</p>
            <p>Please click the button below to verify your email address:</p>
            <a href="{verification_link}" 
               style="background-color: #667eea; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 6px; display: inline-block; 
                      margin: 20px 0;">
                Verify Email Address
            </a>
            <p>Or copy and paste this link in your browser:</p>
            <p><a href="{verification_link}">{verification_link}</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't request this verification, please ignore this email.</p>
        </body>
        </html>
        """
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        
        # Add HTML content
        html_part = MIMEText(body, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        print(f"Verification email sent to {email}")
        return True
        
    except Exception as e:
        print(f"Failed to send verification email to {email}: {str(e)}")
        return False

def initiate_wallet_verification(user_id, wallet_address):
    """Start wallet verification process"""
    try:
        # Generate a unique message for user to sign
        verification_message = generate_wallet_verification_message(user_id, wallet_address)
        
        # Store verification challenge in database
        verification_data = {
            "user_id": user_id,
            "wallet_address": wallet_address,
            "verification_message": verification_message,
            "challenge_created_at": datetime.now(timezone.utc),
            "status": "pending",
            "attempts": 0
        }
        db = get_db_connection()
        # Save to database
        db.wallet_verifications.insert_one(verification_data)
        
        # You could also send notification or email with instructions
        send_wallet_verification_instructions(user_id, wallet_address, verification_message)
        
        return {
            "success": True,
            "verification_message": verification_message,
            "instructions": "Please sign this message with your wallet to verify ownership."
        }
        
    except Exception as e:
        print(f"Failed to initiate wallet verification for {wallet_address}: {str(e)}")
        return {"success": False, "error": str(e)}

def generate_wallet_verification_message(user_id, wallet_address):
    """Generate unique message for wallet signature verification"""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = secrets.token_hex(16)
    
    message = f"""
Verify wallet ownership for YourApp

User ID: {user_id}
Wallet: {wallet_address}
Timestamp: {timestamp}
Nonce: {nonce}

By signing this message, you confirm ownership of this wallet address.
    """.strip()
    
    return message

def verify_wallet_signature(user_id, wallet_address, message, signature):
    """Verify that the signature matches the wallet address"""
    try:
        # This is a simplified version - you'll need proper Web3 signature verification
        from eth_account.messages import encode_defunct
        from eth_account import Account
        
        # Encode message
        encoded_message = encode_defunct(text=message)
        
        # Recover address from signature
        recovered_address = Account.recover_message(encoded_message, signature=signature)
        
        # Check if recovered address matches provided wallet
        if recovered_address.lower() == wallet_address.lower():
            # Update verification status in database
            db = get_db_connection()
            db.users.update_one(
                {"_id": user_id, "wallet_addresses.address": wallet_address},
                {
                    "$set": {
                        "wallet_addresses.$.status": "verified",
                        "wallet_addresses.$.verified_at": datetime.now(timezone.utc),
                        "wallet_addresses.$.verification_method": "signature"
                    }
                }
            )
            
            # Clean up verification record
            db.wallet_verifications.delete_one({
                "user_id": user_id,
                "wallet_address": wallet_address
            })
            
            return {"success": True, "message": "Wallet verified successfully"}
        else:
            return {"success": False, "error": "Signature verification failed"}
            
    except Exception as e:
        print(f"Wallet signature verification error: {str(e)}")
        return {"success": False, "error": "Verification failed"}

def send_wallet_verification_instructions(user_id, wallet_address, message):
    """Send instructions for wallet verification"""
    try:
        user = get_user_by_id(user_id)
        if not user:
            return False
        
        primary_email = get_primary_email(user)
        if not primary_email:
            return False
        
        # Email with instructions
        subject = "Wallet Verification Required"
        body = f"""
        <html>
        <body>
            <h2>Wallet Verification Instructions</h2>
            <p>You've added a new wallet address: <code>{wallet_address}</code></p>
            <p>To verify ownership, please sign the following message with your wallet:</p>
            <div style="background: #f8f9fa; padding: 15px; margin: 15px 0; 
                        border-left: 4px solid #667eea; font-family: monospace;">
                {message}
            </div>
            <p><strong>Steps:</strong></p>
            <ol>
                <li>Open your wallet application (MetaMask, etc.)</li>
                <li>Go to the "Sign Message" or "Personal Sign" feature</li>
                <li>Copy and paste the message above</li>
                <li>Sign the message</li>
                <li>Submit the signature in your profile settings</li>
            </ol>
            <p>This verification ensures only you can use this wallet address.</p>
        </body>
        </html>
        """
        
        # Send email (reuse email sending logic)
        return send_verification_email_generic(primary_email, subject, body)
        
    except Exception as e:
        print(f"Failed to send wallet verification instructions: {str(e)}")
        return False

def send_verification_email_generic(email, subject, body):
    """Generic email sending function"""
    try:
        SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
        SENDER_EMAIL = os.getenv('SENDER_EMAIL')
        SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
        
        if not SENDER_EMAIL or not SENDER_PASSWORD:
            return False
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        
        html_part = MIMEText(body, 'html')
        msg.attach(html_part)
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        return True
        
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False


# Add these classes to your existing helper_functions.py file
# Add these classes to your existing helper_functions.py file

class ElectronicsAuthenticator:
    def __init__(self, db, w3):
        self.db = db
        self.w3 = w3
    
    def verify_single_device(self, serial_number, user_ip, user_agent):
        """Verify a single electronic device"""
        start_time = datetime.now()
        
        # Check database first - using your actual schema
        device = self.db.electronics.find_one({"serialNumber": serial_number})
        
        if not device:
            # Log failed verification
            log_entry = {
                "serialNumber": serial_number,
                "verificationType": "database",
                "userIP": user_ip,
                "userAgent": user_agent,
                "result": "not_found",
                "confidence": 99.9,
                "responseTime": (datetime.now() - start_time).total_seconds() * 1000,
                "flags": ["serial_not_found"],
                "timestamp": datetime.now(),
                "verifiedBy": "system"
            }
            self.db.verificationLogs.insert_one(log_entry)
            
            return {
                "authentic": False,
                "message": "Device not found in authentication database",
                "source": "database",
                "confidence": 0
            }
        
        # Get manufacturer details using your schema
        manufacturer = self.db.manufacturers.find_one({"_id": device.get("manufacturerId")})
        
        result = {
            "authentic": device.get("isAuthentic", False),
            "brand": device.get("brand"),
            "model": device.get("model"),
            "deviceType": device.get("deviceType"),
            "storage": device.get("storage"),
            "color": device.get("color"),
            "manufacturerName": manufacturer.get("companyName") if manufacturer else "Unknown",
            "source": "database",
            "confidence": 95.0 if device.get("isAuthentic") else 99.9
        }
        
        # If device is on blockchain, verify there too
        if device.get("isOnBlockchain"):
            try:
                # Simulate blockchain verification (replace with actual contract call)
                blockchain_verified = True  # contract.functions.verifyDevice(serial_number).call()
                result.update({
                    "source": "blockchain",
                    "blockchainVerified": blockchain_verified,
                    "confidence": 98.5 if blockchain_verified else 85.0
                })
            except Exception as e:
                result["blockchainError"] = str(e)
                result["confidence"] = 85.0
        
        # Log successful verification
        log_entry = {
            "serialNumber": serial_number,
            "verificationType": result["source"],
            "userIP": user_ip,
            "userAgent": user_agent,
            "result": "authentic" if result["authentic"] else "counterfeit",
            "confidence": result["confidence"],
            "responseTime": (datetime.now() - start_time).total_seconds() * 1000,
            "timestamp": datetime.now(),
            "verifiedBy": "consumer"
        }
        self.db.verificationLogs.insert_one(log_entry)
        
        return result
    
    def verify_batch_devices(self, serial_numbers, user_ip):
        """Verify multiple devices at once"""
        results = []
        start_time = datetime.now()
        
        for serial in serial_numbers:
            device = self.db.electronics.find_one({"serialNumber": serial})
            
            if device:
                manufacturer = self.db.manufacturers.find_one({"_id": device.get("manufacturerId")})
                result = {
                    "serialNumber": serial,
                    "authentic": device.get("isAuthentic", False),
                    "brand": device.get("brand", ""),
                    "model": device.get("model", ""),
                    "manufacturerName": manufacturer.get("companyName", "Unknown") if manufacturer else "Unknown",
                    "source": "blockchain" if device.get("isOnBlockchain") else "database"
                }
            else:
                result = {
                    "serialNumber": serial,
                    "authentic": False,
                    "brand": "",
                    "model": "",
                    "manufacturerName": "",
                    "source": "not_found"
                }
            
            results.append(result)
        
        # Log batch verification
        log_entry = {
            "batchSerialNumbers": serial_numbers,
            "batchSize": len(serial_numbers),
            "verificationType": "batch",
            "userIP": user_ip,
            "responseTime": (datetime.now() - start_time).total_seconds() * 1000,
            "timestamp": datetime.now(),
            "verifiedBy": "consumer"
        }
        self.db.verificationLogs.insert_one(log_entry)
        
        return results
    
    # def get_ownership_history(self, serial_number):
    #     """Get ownership transfer history for a device"""
    #     device = self.db.electronics.find_one({"serialNumber": serial_number})
    #     if not device:
    #         return None
        
    #     history = list(self.db.ownershipHistory.find({"serialNumber": serial_number}).sort("transferDate", 1))
        
    #     # Format history for display
    #     formatted_history = []
    #     for record in history:
    #         formatted_record = {
    #             "from": record.get("previousOwner", {}).get("name", "Unknown"),
    #             "to": record.get("newOwner", {}).get("name", "Unknown"),
    #             "date": record.get("transferDate"),
    #             "reason": record.get("transferReason", "Transfer"),
    #             "price": record.get("salePrice", 0),
    #             "invoice": record.get("invoiceNumber", "N/A")
    #         }
    #         formatted_history.append(formatted_record)
        
    #     return formatted_history


class DatabaseManager:
    def __init__(self, db):
        self.db = db
    
    # def get_device_details(self, serial_number):
    #     """Get detailed device information"""
    #     device = self.db.electronics.find_one({"serialNumber": serial_number})
        
    #     if not device:
    #         return None
        
    #     # Get manufacturer details
    #     manufacturer = self.db.manufacturers.find_one({"_id": device.get("manufacturerId")})
        
    #     # Get current owner details
    #     current_owner = self.db.users.find_one({"_id": device.get("currentOwnerId")})
        
    #     result = {
    #         "serialNumber": device.get("serialNumber"),
    #         "brand": device.get("brand"),
    #         "model": device.get("model"),
    #         "deviceType": device.get("deviceType"),
    #         "storage": device.get("storage"),
    #         "color": device.get("color"),
    #         "processor": device.get("processor"),
    #         "screenSize": device.get("screenSize"),
    #         "camera": device.get("camera"),
    #         "operatingSystem": device.get("operatingSystem"),
    #         "retailPrice": device.get("retailPrice"),
    #         "manufacturingDate": device.get("manufacturingDate"),
    #         "registrationDate": device.get("registrationDate"),
    #         "batchNumber": device.get("batchNumber"),
    #         "warrantyPeriod": device.get("warrantyPeriod"),
    #         "manufacturer": {
    #             "name": manufacturer.get("companyName") if manufacturer else "Unknown",
    #             "country": manufacturer.get("country") if manufacturer else "Unknown",
    #             "established": manufacturer.get("establishedYear") if manufacturer else None
    #         },
    #         "currentOwner": {
    #             "name": current_owner.get("name") if current_owner else "Unknown",
    #             "type": current_owner.get("userType") if current_owner else "Unknown"
    #         },
    #         "isOnBlockchain": device.get("isOnBlockchain", False),
    #         "isAuthentic": device.get("isAuthentic", False),
    #         "blockchainTxHash": device.get("blockchainTxHash")
    #     }
        
    #     return result
    
    def get_system_stats(self):
        """Get system statistics for research analysis"""
        # Device statistics
        total_devices = self.db.electronics.count_documents({})
        authentic_devices = self.db.electronics.count_documents({"isAuthentic": True})
        blockchain_devices = self.db.electronics.count_documents({"isOnBlockchain": True})
        
        # Verification statistics
        total_verifications = self.db.verificationLogs.count_documents({})
        successful_verifications = self.db.verificationLogs.count_documents({"result": "authentic"})
        counterfeit_detections = self.db.verificationLogs.count_documents({"result": "counterfeit"})
        
        # Response time analysis
        recent_logs = list(self.db.verificationLogs.find({"responseTime": {"$exists": True}}).limit(1000))
        avg_response_time = 0
        if recent_logs:
            avg_response_time = sum(log.get("responseTime", 0) for log in recent_logs) / len(recent_logs)
        
        # Ownership transfers
        total_transfers = self.db.ownershipHistory.count_documents({})
        
        # Manufacturer statistics
        total_manufacturers = self.db.manufacturers.count_documents({})
        verified_manufacturers = self.db.manufacturers.count_documents({"isVerified": True})
        
        stats = {
            "devices": {
                "total": total_devices,
                "authentic": authentic_devices,
                "blockchain": blockchain_devices,
                "database": total_devices - blockchain_devices,
                "authenticity_rate": round((authentic_devices / total_devices * 100), 2) if total_devices > 0 else 0
            },
            "verifications": {
                "total": total_verifications,
                "successful": successful_verifications,
                "counterfeit_detected": counterfeit_detections,
                "success_rate": round((successful_verifications / total_verifications * 100), 2) if total_verifications > 0 else 0,
                "average_response_time": round(avg_response_time, 2)
            },
            "ownership": {
                "total_transfers": total_transfers
            },
            "manufacturers": {
                "total": total_manufacturers,
                "verified": verified_manufacturers,
                "verification_rate": round((verified_manufacturers / total_manufacturers * 100), 2) if total_manufacturers > 0 else 0
            },
            "last_updated": datetime.now().isoformat()
        }
        
        return stats
    
    # def seed_sample_data(self):
    #     """Seed database with sample data for demonstration"""
    #     # Sample manufacturers (if not exists)
    #     manufacturers_data = [
    #         {
    #             "walletAddress": "0x742d35Cc622C4532c0532255c87A59B852b74f8d",
    #             "companyName": "Apple Inc",
    #             "email": "verify@apple.com",
    #             "country": "United States",
    #             "establishedYear": 1976,
    #             "headquarters": "Cupertino, California",
    #             "isVerified": True,
    #             "verificationDate": datetime.now(),
    #             "annualProduction": 230000000,
    #             "createdAt": datetime.now()
    #         },
    #         {
    #             "walletAddress": "0x8ba1f109551bD432803012645Hac136c461c11B6",
    #             "companyName": "Samsung Electronics",
    #             "email": "auth@samsung.com",
    #             "country": "South Korea",
    #             "establishedYear": 1969,
    #             "headquarters": "Seoul, South Korea",
    #             "isVerified": True,
    #             "verificationDate": datetime.now(),
    #             "annualProduction": 300000000,
    #             "createdAt": datetime.now()
    #         }
    #     ]
        
    #     inserted_manufacturers = 0
    #     for manufacturer in manufacturers_data:
    #         if not self.db.manufacturers.find_one({"companyName": manufacturer["companyName"]}):
    #             result = self.db.manufacturers.insert_one(manufacturer)
    #             manufacturer["_id"] = result.inserted_id
    #             inserted_manufacturers += 1
        
    #     # Get manufacturer IDs
    #     apple_manufacturer = self.db.manufacturers.find_one({"companyName": "Apple Inc"})
    #     samsung_manufacturer = self.db.manufacturers.find_one({"companyName": "Samsung Electronics"})
        
    #     if not apple_manufacturer or not samsung_manufacturer:
    #         return {"error": "Failed to create manufacturers"}
        
    #     apple_id = apple_manufacturer["_id"]
    #     samsung_id = samsung_manufacturer["_id"]
        
    #     # Sample devices
    #     sample_devices = [
    #         {
    #             "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
    #             "brand": "Apple",
    #             "model": "iPhone 15 Pro",
    #             "deviceType": "Smartphone",
    #             "storage": "128GB",
    #             "color": "Titanium Blue",
    #             "processor": "A17 Pro",
    #             "screenSize": "6.1 inches",
    #             "camera": "48MP Triple Camera",
    #             "operatingSystem": "iOS 17",
    #             "retailPrice": 999,
    #             "manufacturerId": apple_id,
    #             "currentOwnerId": apple_id,
    #             "isOnBlockchain": True,
    #             "manufacturingDate": datetime.now() - timedelta(days=30),
    #             "registrationDate": datetime.now() - timedelta(days=29),
    #             "batchNumber": "APL-2024-001",
    #             "warrantyPeriod": "1 year",
    #             "isAuthentic": True,
    #             "blockchainTxHash": "0x1234567890abcdef1234567890abcdef12345678",
    #             "createdAt": datetime.now()
    #         },
    #         {
    #             "serialNumber": "SAMS-GAL-S24-256-2024-SM789012",
    #             "brand": "Samsung",
    #             "model": "Galaxy S24 Ultra",
    #             "deviceType": "Smartphone", 
    #             "storage": "256GB",
    #             "color": "Phantom Black",
    #             "processor": "Snapdragon 8 Gen 3",
    #             "screenSize": "6.8 inches",
    #             "camera": "200MP Quad Camera",
    #             "operatingSystem": "Android 14",
    #             "retailPrice": 1299,
    #             "manufacturerId": samsung_id,
    #             "currentOwnerId": samsung_id,
    #             "isOnBlockchain": False,
    #             "manufacturingDate": datetime.now() - timedelta(days=20),
    #             "registrationDate": datetime.now() - timedelta(days=19),
    #             "batchNumber": "SAM-2024-002",
    #             "warrantyPeriod": "1 year",
    #             "isAuthentic": True,
    #             "createdAt": datetime.now()
    #         },
    #         # Add some blockchain verified devices
    #         {
    #             "serialNumber": "APPLE001",
    #             "brand": "Apple",
    #             "model": "iPhone 14",
    #             "deviceType": "Smartphone",
    #             "storage": "256GB",
    #             "color": "Space Black",
    #             "processor": "A16 Bionic",
    #             "manufacturerId": apple_id,
    #             "currentOwnerId": apple_id,
    #             "isOnBlockchain": True,
    #             "isAuthentic": True,
    #             "createdAt": datetime.now()
    #         },
    #         {
    #             "serialNumber": "NIKE001",
    #             "brand": "Nike",
    #             "model": "Air Jordan 1",
    #             "deviceType": "Footwear",
    #             "storage": "N/A",
    #             "color": "Bred",
    #             "manufacturerId": apple_id,  # Using apple_id as placeholder
    #             "currentOwnerId": apple_id,
    #             "isOnBlockchain": True,
    #             "isAuthentic": True,
    #             "createdAt": datetime.now()
    #         },
    #         {
    #             "serialNumber": "GUCCI001",
    #             "brand": "Gucci",
    #             "model": "GG Marmont",
    #             "deviceType": "Handbag",
    #             "storage": "N/A",
    #             "color": "Black",
    #             "manufacturerId": apple_id,  # Using apple_id as placeholder
    #             "currentOwnerId": apple_id,
    #             "isOnBlockchain": True,
    #             "isAuthentic": True,
    #             "createdAt": datetime.now()
    #         }
    #     ]
        
    #     # Insert devices if not exists
    #     inserted_count = 0
    #     for device in sample_devices:
    #         if not self.db.electronics.find_one({"serialNumber": device["serialNumber"]}):
    #             self.db.electronics.insert_one(device)
    #             inserted_count += 1
        
    #     # Add some sample ownership history
    #     sample_ownership = [
    #         {
    #             "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
    #             "previousOwner": {
    #                 "id": apple_id,
    #                 "name": "Apple Inc",
    #                 "type": "manufacturer"
    #             },
    #             "newOwner": {
    #                 "id": apple_id,
    #                 "name": "Apple Store",
    #                 "type": "retailer"
    #             },
    #             "transferDate": datetime.now() - timedelta(days=15),
    #             "transferReason": "Initial Sale",
    #             "salePrice": 999,
    #             "transferMethod": "retail_sale",
    #             "invoiceNumber": "APL-2024-INV-001",
    #             "createdAt": datetime.now()
    #         }
    #     ]
        
    #     ownership_inserted = 0
    #     for ownership in sample_ownership:
    #         if not self.db.ownershipHistory.find_one({"serialNumber": ownership["serialNumber"]}):
    #             self.db.ownershipHistory.insert_one(ownership)
    #             ownership_inserted += 1
        
    #     return {
    #         "message": f"Sample data seeded successfully",
    #         "manufacturers_inserted": inserted_manufacturers,
    #         "devices_inserted": inserted_count,
    #         "ownership_records_inserted": ownership_inserted,
    #         "manufacturers_ready": True
    #     }
    
#actual blockchain verification
def generate_specification_hash(product_data):
    """Generate specification hash for blockchain registration"""
    spec_string = f"{product_data['name']}{product_data['category']}{product_data['serialNumber']}{product_data['price']}"
    return "0x" + hashlib.sha256(spec_string.encode()).hexdigest()[:32]

def validate_manufacturer_wallet(wallet_address, user_wallets):
    """Validate that the wallet belongs to the manufacturer"""
    return wallet_address in user_wallets

def log_product_registration(product_data, registration_type, transaction_hash=None):
    """Log product registration for research tracking"""
    log_entry = {
        "serialNumber": product_data['serialNumber'],
        "registration_type": registration_type,
        "transactionHash": transaction_hash,
        "timestamp": datetime.now(timezone.utc),
        "manufacturerWallet": product_data['manufacturerWallet']
    }
    
    # Save to registration_logs collection
    try:
        db = get_db_connection()
        db.registration_logs.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log registration: {e}")

def get_manufacturer_statistics(manufacturer_wallet):
    """Get comprehensive statistics for manufacturer dashboard"""
    try:
        db = get_db_connection()
        
        # Product counts by registration type
        pipeline = [
            {"$match": {"manufacturerWallet": manufacturer_wallet}},
            {"$group": {
                "_id": "$registration_type",
                "count": {"$sum": 1}
            }}
        ]
        
        registration_stats = list(db.products.aggregate(pipeline))
        
        # Verification counts for manufacturer's products
        manufacturer_products = list(db.products.find(
            {"manufacturerWallet": manufacturer_wallet}, 
            {"serialNumber": 1}
        ))
        
        serial_numbers = [p["serialNumber"] for p in manufacturer_products]
        verification_count = db.verifications.count_documents({
            "serialNumber": {"$in": serial_numbers}
        }) if serial_numbers else 0
        
        return {
            "registration_stats": registration_stats,
            "total_verifications": verification_count,
            "total_products": len(manufacturer_products)
        }
        
    except Exception as e:
        print(f"Error getting manufacturer statistics: {e}")
        return {}
#actual blokchain verification code
def generate_specification_hash(product_data):
    """Generate specification hash for blockchain registration"""
    spec_string = f"{product_data['name']}{product_data['category']}{product_data['serialNumber']}{product_data['price']}"
    return "0x" + hashlib.sha256(spec_string.encode()).hexdigest()[:32]

def validate_manufacturer_wallet(wallet_address, user_wallets):
    """Validate that the wallet belongs to the manufacturer"""
    return wallet_address in user_wallets

def log_product_registration(product_data, registration_type, transaction_hash=None):
    """Log product registration for research tracking"""
    log_entry = {
        "serialNumber": product_data['serialNumber'],
        "registration_type": registration_type,
        "transactionHash": transaction_hash,
        "timestamp": datetime.now(timezone.utc),
        "manufacturerWallet": product_data['manufacturerWallet']
    }
    
    # Save to registration_logs collection
    try:
        db = get_db_connection()
        db.registration_logs.insert_one(log_entry)
    except Exception as e:
        print(f"Failed to log registration: {e}")

def get_manufacturer_statistics(manufacturer_wallet):
    """Get comprehensive statistics for manufacturer dashboard"""
    try:
        db = get_db_connection()
        
        # Product counts by registration type
        pipeline = [
            {"$match": {"manufacturerWallet": manufacturer_wallet}},
            {"$group": {
                "_id": "$registration_type",
                "count": {"$sum": 1}
            }}
        ]
        
        registration_stats = list(db.products.aggregate(pipeline))
        
        # Verification counts for manufacturer's products
        manufacturer_products = list(db.products.find(
            {"manufacturerWallet": manufacturer_wallet}, 
            {"serialNumber": 1}
        ))
        
        serial_numbers = [p["serialNumber"] for p in manufacturer_products]
        verification_count = db.verifications.count_documents({
            "serialNumber": {"$in": serial_numbers}
        }) if serial_numbers else 0
        
        return {
            "registration_stats": registration_stats,
            "total_verifications": verification_count,
            "total_products": len(manufacturer_products)
        }
        
    except Exception as e:
        print(f"Error getting manufacturer statistics: {e}")
        return {}
    
# Helper function to format user profile data
def format_user_profile(user):
    """Format user data for profile response"""
    if not user:
        return None
        
    profile_data = {
        "id": str(user.get('_id')),
        "name": user.get('name'),
        "role": user.get('role'),
        "emails": user.get('emails', []),
        "primary_email": get_primary_email(user),
        "verification_status": user.get('verification_status'),
        "created_at": user.get('created_at')
    }
    
    if user.get('role') == 'manufacturer':
        profile_data.update({
            "wallet_addresses": user.get('wallet_addresses', []),
            "primary_wallet": get_primary_wallet(user),
            "verified_wallets": get_verified_wallets(user),
            "company_names": user.get('company_names', []),
            "current_company_name": get_current_company_name(user)
        })
    
    return profile_data

def validate_product_data(data):
    required_fields = ["serialNumber", "brand", "model", "deviceType"]
    for field in required_fields:
        if not data.get(field):
            raise ValidationError(f"{field} is required")
    
    if len(data["serialNumber"]) < 3:
        raise ValidationError("Serial number must be at least 3 characters long")
    
    valid_device_types = [
        "Smartphone", "Laptop", "Tablet", "Desktop", "Monitor", 
        "Camera", "Audio Device", "Gaming Console", "Smart Watch", "Other"
    ]
    if data["deviceType"] not in valid_device_types:
        raise ValidationError("Invalid device type")
    
    # Validate Ethereum address format for transfers
    if data.get("newOwnerAddress"):
        if not re.match(r'^0x[a-fA-F0-9]{40}$', data["newOwnerAddress"]):
            raise ValidationError("Invalid Ethereum wallet address format")

def create_ownership_transfer(transfer_data):
    """Create ownership transfer record"""
    db = get_db_connection()
    result = db.ownership_transfers.insert_one(transfer_data)
    return str(result.inserted_id)

def get_ownership_history_by_serial(serial_number):
    """Get ownership history for a product"""
    db = get_db_connection()
    return list(db.ownership_transfers.find({"serial_number": serial_number}).sort("transfer_date", 1))

def validate_ownership_transfer(data):
    """Validate ownership transfer data"""
    required_fields = ["serialNumber", "newOwnerAddress", "transferReason"]
    for field in required_fields:
        if not data.get(field):
            raise ValidationError(f"{field} is required")
    
    # Validate Ethereum address
    if not re.match(r'^0x[a-fA-F0-9]{40}$', data["newOwnerAddress"]):
        raise ValidationError("Invalid Ethereum wallet address format")
    
    valid_reasons = ["Sale", "Gift", "Warranty Replacement", "Return/Exchange", "Business Transfer", "Other"]
    if data["transferReason"] not in valid_reasons:
        raise ValidationError("Invalid transfer reason")
    
    # Validate sale price if provided
    sale_price = data.get("salePrice", 0)
    if sale_price and float(sale_price) < 0:
        raise ValidationError("Sale price cannot be negative")

def log_verification_attempt(db, log_data):
    """Log a verification attempt"""
    try:
        # Ensure the collection exists
        if 'verification_logs' not in db.list_collection_names():
            db.create_collection('verification_logs')
        
        db.verifications.insert_one(log_data)
        print(f"Verification attempt logged for {log_data.get('serial_number')}")
    except Exception as e:
        print(f"Verification logging failed: {e}")

def get_registration_transaction(serial_number):
    """
    Get the registration transaction hash for a device
    This should be stored when devices are registered on the blockchain
    """
    try:
        db = get_db_connection()
        if db is None:
            return None
            
        # Look for the transaction hash in your products collection
        product = db.products.find_one({"serial_number": serial_number})
        
        if product:
            # Try different possible field names where tx hash might be stored
            tx_hash = (product.get("transaction_hash") or 
                      product.get("registration_tx_hash") or 
                      product.get("blockchain_tx") or
                      product.get("tx_hash"))
            
            if tx_hash:
                return tx_hash
            
        # If not found in products collection, check if you have a separate transactions collection
        if 'blockchain_transactions' in db.list_collection_names():
            tx_record = db.blockchain_transactions.find_one({"serial_number": serial_number})
            if tx_record:
                return tx_record.get("transaction_hash")
        
        # If no real transaction hash found, you could return None or a placeholder
        return None
        
    except Exception as e:
        print(f"Error getting registration transaction: {e}")
        return None



# Update your database schema to store transaction hashes
def store_registration_transaction(serial_number, tx_hash):
    """
    Store the registration transaction hash when a device is registered
    Call this function when you register a device on the blockchain
    """
    try:
        db = get_db_connection()
        if db is None:
            return False
            
        # Update the product record with the transaction hash
        result = db.products.update_one(
            {"serial_number": serial_number},
            {
                "$set": {
                    "transaction_hash": tx_hash,
                    "blockchain_verified": True,
                    "blockchain_registered_at": datetime.now(timezone.utc)
                }
            }
        )
        
        # Optionally, also store in a separate transactions collection
        db.blockchain_transactions.insert_one({
            "serial_number": serial_number,
            "transaction_hash": tx_hash,
            "network": "sepolia",
            "timestamp": datetime.now(timezone.utc),
            "status": "confirmed"
        })
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"Error storing transaction hash: {e}")
        return False
    
def verify_product_on_blockchain(serial_number):
    """Verify product exists on blockchain"""
    try:
        # Get environment variables
        contract_address = os.getenv('CONTRACT_ADDRESS')
        rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
        
        if not contract_address:
            print("CONTRACT_ADDRESS not configured")
            return {"verified": False, "error": "Contract address not configured"}
            
        if not rpc_url:
            print("BLOCKCHAIN_RPC_URL not configured")
            return {"verified": False, "error": "Blockchain RPC URL not configured"}
        
        print(f"Connecting to blockchain at {rpc_url}")
        print(f"Using contract address: {contract_address}")
        
        # Connect to blockchain
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Check connection
        if not w3.is_connected():
            print("Blockchain connection failed")
            return {"verified": False, "error": "Unable to connect to blockchain"}
        
        print("Blockchain connection successful")
        
        # Create contract instance
        try:
            checksum_address = Web3.to_checksum_address(contract_address)
            contract = w3.eth.contract(
                address=checksum_address,
                abi=contract_abi
            )
            print(f"Contract instance created for {checksum_address}")
        except Exception as contract_error:
            print(f"Contract creation failed: {contract_error}")
            return {"verified": False, "error": f"Invalid contract address: {str(contract_error)}"}
        
        # Call contract function
        try:
            print(f"Calling verifyDevice for serial: {serial_number}")
            product_data = contract.functions.verifyDevice(serial_number).call()
            print(f"Contract response: {product_data}")
            
            # Unpack the response tuple
            # Format: (exists, isAuthentic, brand, model, deviceType, manufacturerName, currentOwner)
            if len(product_data) >= 7:
                exists, is_authentic, brand, model, device_type, manufacturer_name, current_owner = product_data[:7]
                
                if exists and is_authentic:
                    # Try to get the registration transaction hash from your database
                    # You should store this when devices are registered
                    registration_tx = get_registration_transaction(serial_number)  # Implement this function
                    
                    return {
                        "verified": True,
                        "transaction_hash": registration_tx,  # Add this field for the main response
                        "blockchain_data": {
                            "exists": exists,
                            "isAuthentic": is_authentic,
                            "brand": brand,
                            "model": model,
                            "deviceType": device_type,
                            "manufacturerName": manufacturer_name,
                            "currentOwner": current_owner
                        },
                        "contract_address": contract_address,
                        "network": "sepolia",
                        "proof": {
                            "transaction_hash": registration_tx,
                            "contract_address": contract_address,
                            "network": "sepolia",
                            "explorer_links": {
                                "contract": f"https://sepolia.etherscan.io/address/{contract_address}",
                                "transaction": f"https://sepolia.etherscan.io/tx/{registration_tx}" if registration_tx else None
                            }
                        }
                    }
                else:
                    return {
                        "verified": False,
                        "error": f"Product not found or not authentic on blockchain. Exists: {exists}, Authentic: {is_authentic}"
                    }
            else:
                return {
                    "verified": False,
                    "error": f"Unexpected contract response format: {product_data}"
                }
                
        except Exception as contract_error:
            print(f"Contract call failed: {contract_error}")
            return {"verified": False, "error": f"Contract call failed: {str(contract_error)}"}
            
    except Exception as e:
        print(f"Blockchain verification error: {e}")
        return {"verified": False, "error": f"Blockchain verification failed: {str(e)}"}



def get_device_details(serial_number):
    """Get detailed device information from blockchain"""
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address), 
            abi=contract_abi
        )
        
        # Call getDeviceDetails function
        result = contract.functions.getDeviceDetails(serial_number).call()
        
        # result returns: (brand, model, deviceType, storageData, color, manufacturerName, currentOwner, manufacturingDate)
        brand, model, device_type, storage_data, color, manufacturer_name, current_owner, manufacturing_date = result
        
        return {
            "success": True,
             "data": {
                "brand": brand,
                "model": model,
                "deviceType": device_type,
                "storageData": storage_data,
                "color": color,
                "manufacturerName": manufacturer_name,
                "currentOwner": current_owner,
                "manufacturingDate": manufacturing_date
            }
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
    
def get_ownership_history(serial_number):
    """Get ownership history from blockchain"""
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address), 
            abi=contract_abi
        )
        
        # Call getOwnershipHistory function
        result = contract.functions.getOwnershipHistory(serial_number).call()
        
        # result returns: (previousOwners, newOwners, transferDates, transferReasons, salePrices)
        previous_owners, new_owners, transfer_dates, transfer_reasons, sale_prices = result
        
        history = []
        for i in range(len(previous_owners)):
             history.append({
                "previousOwner": previous_owners[i],
                "newOwner": new_owners[i],
                "transferDate": transfer_dates[i],
                "transferReason": transfer_reasons[i],
                "salePrice": sale_prices[i]
            })
        
        return {"success": True, "history": history}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# Helper functions for profile data

def get_primary_email(user):
    """Get user's primary email"""
    emails = user.get('emails', [])
    if not emails:
        return user.get('email')  # fallback to single email field
    
    # Find primary email
    for email in emails:
        if isinstance(email, dict) and email.get('is_primary'):
            return email.get('email')
    
    # Return first email if no primary found
    if isinstance(emails[0], dict):
        return emails[0].get('email')
    return emails[0]


def get_primary_wallet(user):
    """Get user's primary wallet address"""
    return user.get('primary_wallet') or user.get('wallet_address')


def get_verified_wallets(user):
    """Get list of verified wallet addresses"""
    wallet_addresses = user.get('wallet_addresses', [])
    verified_wallets = []
    
    for wallet in wallet_addresses:
        if isinstance(wallet, dict) and wallet.get('is_verified'):
            verified_wallets.append(wallet.get('address'))
    
    return verified_wallets


def get_current_company_name(user):
    """Get user's current company name"""
    return user.get('current_company_name') or user.get('company_name')


def get_manufacturer_product_count(user_id):
    """Get total number of products registered by manufacturer"""
    try:
        db = get_db_connection()
        return db.products.count_documents({"manufacturer_id": user_id})
    except:
        return 0


def get_manufacturer_sales_count(user_id):
    """Get total number of sales/transfers by manufacturer"""
    try:
        db = get_db_connection()
        return db.transactions.count_documents({
            "from_user_id": user_id,
            "transaction_type": "sale"
        })
    except:
        return 0
    
def get_customer_purchase_count(user_id):
    """Get total number of purchases by customer"""
    try:
        db = get_db_connection()
        return db.transactions.count_documents({
            "to_user_id": user_id,
            "transaction_type": "sale"
        })
    except:
        return 0


def get_customer_owned_products_count(user_id):
    """Get total number of products owned by customer"""
    try:
        db = get_db_connection()
        return db.products.count_documents({"current_owner_id": user_id})
    except:
        return 0


def get_customer_last_purchase_date(user_id):
    """Get customer's last purchase date"""
    try:
        db = get_db_connection()
        last_purchase = db.transactions.find_one(
            {"to_user_id": user_id, "transaction_type": "sale"},
            sort=[("created_at", -1)]
        )
        return last_purchase.get('created_at') if last_purchase else None
    except:
        return None


def blacklist_token(token):
    """Add token to blacklist (implement based on your token strategy)"""
    try:
        db = get_db_connection()
        db.blacklisted_tokens.insert_one({
            "token": token,
            "blacklisted_at": datetime.now(timezone.utc)
        })
        print(f"Token blacklisted: {token[:20]}...")
    except Exception as e:
        print(f"Failed to blacklist token: {e}")

def register_device_blockchain(serial_number, device_data):
    """
    Actually register a device on the blockchain
    Returns transaction hash if successful
    """
    try:
        contract_address = os.getenv('CONTRACT_ADDRESS')
        rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
        private_key = os.getenv('PRIVATE_KEY')  # For signing transactions
        
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        if not w3.is_connected():
            return {"success": False, "error": "Blockchain connection failed"}
        
        # Create contract instance
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=contract_abi
        )
        
        # Get account from private key
        account = w3.eth.account.from_key(private_key)
        
        # Build transaction
        transaction = contract.functions.registerDevice(
            serial_number,
            device_data.get('brand', ''),
            device_data.get('model', ''),
            device_data.get('device_type', ''),
            device_data.get('manufacturer_name', '')
        ).build_transaction({
            'from': account.address,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gas': 300000,
            'gasPrice': w3.to_wei('20', 'gwei')
        })
        
        # Sign and send transaction
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Wait for confirmation (optional)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        return {
            "success": True,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}