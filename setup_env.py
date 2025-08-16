#!/usr/bin/env python3
"""
Quick setup script for environment variables
"""

import os
import secrets

def create_env_file():
    """Create .env file with default values"""
    
    # Generate secure random keys
    secret_key = secrets.token_hex(32)
    jwt_secret = secrets.token_hex(32)
    
    env_content = f"""# Flask Configuration
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY={secret_key}

# JWT Configuration
JWT_SECRET_KEY={jwt_secret}

# Database Configuration
MONGO_URI=mongodb://localhost:27017/product_auth_db
TEST_MONGO_URI=mongodb://localhost:27017/test_product_auth_db

# Blockchain Configuration (update these with your actual values)
WEB3_PROVIDER=http://127.0.0.1:7545
CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890
CONTRACT_ABI_PATH=contract/contract_abi.json

# Server Configuration
PORT=5000
HOST=0.0.0.0

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/product_auth.log
"""

    if os.path.exists('.env'):
        response = input(".env file already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            return False
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("✅ .env file created successfully!")
        print("\n📝 Next steps:")
        print("1. Update MONGO_URI if your MongoDB is running on a different host/port")
        print("2. Update WEB3_PROVIDER with your Ethereum node URL (e.g., Ganache)")
        print("3. Update CONTRACT_ADDRESS with your deployed smart contract address")
        print("4. Update CONTRACT_ABI_PATH with the path to your contract ABI file")
        print("\n🚀 You can now run: python app.py")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

def check_requirements():
    """Check if required directories exist"""
    dirs = ['logs', 'contracts']
    
    for dir_name in dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"✅ Created directory: {dir_name}/")

def create_dummy_contract_abi():
    """Create a dummy contract ABI file for testing"""
    contracts_dir = 'contracts'
    if not os.path.exists(contracts_dir):
        os.makedirs(contracts_dir)
    
    abi_path = os.path.join(contracts_dir, 'contract_abi.json')
    
    if not os.path.exists(abi_path):
        dummy_abi = {
            "abi": [
                {
                    "inputs": [{"name": "manufacturer", "type": "address"}],
                    "name": "authorizeManufacturer",
                    "outputs": [],
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "serialNumber", "type": "string"},
                        {"name": "productName", "type": "string"},
                        {"name": "category", "type": "string"}
                    ],
                    "name": "registerProduct",
                    "outputs": [],
                    "type": "function"
                },
                {
                    "inputs": [{"name": "serialNumber", "type": "string"}],
                    "name": "verifyProduct",
                    "outputs": [
                        {"name": "verified", "type": "bool"},
                        {"name": "manufacturer", "type": "address"},
                        {"name": "productName", "type": "string"},
                        {"name": "category", "type": "string"},
                        {"name": "timestamp", "type": "uint256"}
                    ],
                    "type": "function"
                }
            ]
        }
        
        try:
            import json
            with open(abi_path, 'w') as f:
                json.dump(dummy_abi, f, indent=2)
            print(f"✅ Created dummy contract ABI: {abi_path}")
            print("⚠️  Remember to replace this with your actual contract ABI!")
        except Exception as e:
            print(f"❌ Error creating contract ABI: {e}")

if __name__ == "__main__":
    print("🔧 Setting up Product Authentication API environment...")
    print("=" * 50)
    
    # Check and create required directories
    check_requirements()
    
    # Create .env file
    if create_env_file():
        # Create dummy contract ABI
        create_dummy_contract_abi()
        
        print("\n✅ Setup completed successfully!")
        print("\n🔍 To verify your setup:")
        print("1. Check if MongoDB is running: mongod --version")
        print("2. Start your Ethereum node (e.g., Ganache)")
        print("3. Deploy your smart contract")
        print("4. Update .env with actual values")
        print("5. Run: python app.py")
    else:
        print("\n❌ Setup failed. Please check the errors above.")



# py
# [2025-08-16 11:33:57,990] ERROR in app: Failed to initialize blockchain service: [Errno 2] No such file or directory: 'contract/contract_abi.json'
# Failed to create indexes: type object 'User' has no attribute 'collection'
# [2025-08-16 11:33:58,055] INFO in app: Database indexes created/verified
# Traceback (most recent call last):
#   File "/home/damilola/Desktop/product-verification-backend/app.py", line 140, in <module>
#     @app.before_request
#      ^^^^^^^^^^^^^^^^^^^^^^^^
# AttributeError: 'Flask' object has no attribute 'before_request'. Did you mean: 'before_request'?