#!/usr/bin/env python3
"""
Simplified startup script that handles missing directories and files
"""

import os
import json
import sys

def create_required_directories():
    """Create required directories if they don't exist"""
    directories = ['logs', '.contract', 'contracts']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created directory: {directory}/")

def create_dummy_abi_if_missing():
    """Create a dummy ABI file if the specified one doesn't exist"""
    abi_path = os.getenv('CONTRACT_ABI_PATH', '.contract/contract_abi.json')
    
    if not os.path.exists(abi_path):
        print(f"⚠️ ABI file not found at {abi_path}, creating dummy ABI...")
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(abi_path), exist_ok=True)
        
        dummy_abi = {
            "abi": [
                {
                    "inputs": [{"name": "manufacturer", "type": "address"}],
                    "name": "authorizeManufacturer",
                    "outputs": [],
                    "stateMutability": "nonpayable",
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
                    "stateMutability": "nonpayable",
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
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
        }
        
        try:
            with open(abi_path, 'w') as f:
                json.dump(dummy_abi, f, indent=2)
            print(f"✅ Created dummy ABI file: {abi_path}")
        except Exception as e:
            print(f"❌ Error creating ABI file: {e}")

def check_env_variables():
    """Check if required environment variables are set"""
    required_vars = ['MONGO_URI', 'CONTRACT_ADDRESS', 'JWT_SECRET']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"⚠️ Missing environment variables: {', '.join(missing_vars)}")
        print("Make sure your .env file is properly configured.")
        return False
    return True

def main():
    """Main startup function"""
    print("🚀 Starting Product Authentication API...")
    print("=" * 50)
    
    # Load environment variables from .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Loaded environment variables from .env file")
    except ImportError:
        print("⚠️ python-dotenv not installed, using system environment variables")
    except Exception as e:
        print(f"⚠️ Error loading .env file: {e}")
    
    # Create required directories
    create_required_directories()
    
    # Create dummy ABI if missing
    create_dummy_abi_if_missing()
    
    # Check environment variables
    if not check_env_variables():
        print("\n❌ Environment setup incomplete. Please check your .env file.")
        sys.exit(1)
    
    print("\n✅ Setup complete, starting Flask application...")
    print("=" * 50)
    
    # Import and run the Flask app
    try:
        from app import app
        
        # Run the application
        port = int(os.getenv('PORT', 5000))
        debug = os.getenv('FLASK_ENV') == 'development'
        
        print(f"🌐 Server starting on http://0.0.0.0:{port}")
        print("📝 API Documentation available at /")
        print("🔍 Health check available at /health")
        
        app.run(
            host='0.0.0.0',
            port=port,
            debug=debug,
            threaded=True
        )
        
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()