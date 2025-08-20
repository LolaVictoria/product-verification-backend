# blockchain_test.py - Test blockchain connection and contract interactions
import os
from dotenv import load_dotenv
from helper_functions import blockchain_service

load_dotenv()

def test_blockchain_connection():
    """Test basic blockchain connection"""
    print("🔗 Testing Blockchain Connection...")
    print(f"Connected: {blockchain_service.connected}")
    
    if blockchain_service.connected:
        try:
            # Test basic connection
            latest_block = blockchain_service.web3.eth.get_block('latest')
            print(f"✅ Connected to blockchain. Latest block: {latest_block['number']}")
            
            # Test contract connection
            contract_owner = blockchain_service.contract.functions.owner().call()
            print(f"✅ Contract owner: {contract_owner}")
            
            return True
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False
    else:
        print("❌ Not connected to blockchain")
        return False

def test_product_verification():
    """Test product verification functions"""
    print("\n📦 Testing Product Verification...")
    
    # Test with a known product (you'll need to register one first)
    test_serial = "TEST123"
    
    try:
        # Test simple verification
        is_verified = blockchain_service.is_product_verified_simple(test_serial)
        print(f"Product {test_serial} verified (simple): {is_verified}")
        
        # Test detailed verification
        details = blockchain_service.get_product_details_blockchain(test_serial)
        if details:
            print(f"Product details: {details}")
        else:
            print(f"No details found for product {test_serial}")
            
    except Exception as e:
        print(f"❌ Verification test failed: {e}")

def test_manufacturer_authorization():
    """Test manufacturer authorization functions"""
    print("\n👤 Testing Manufacturer Authorization...")
    
    # Test with your wallet address from .env
    test_address = os.getenv('TEST_MANUFACTURER_ADDRESS', '0x742d35Cc6634C0532925a3b8D400AD96Cfb4c001')
    
    try:
        is_authorized = blockchain_service.is_manufacturer_authorized(test_address)
        print(f"Manufacturer {test_address} authorized: {is_authorized}")
        
    except Exception as e:
        print(f"❌ Authorization test failed: {e}")

def test_product_registration():
    """Test product registration (requires authorized manufacturer)"""
    print("\n📝 Testing Product Registration...")
    
    if not blockchain_service.connected or not blockchain_service.account:
        print("❌ Cannot test registration: no account configured")
        return
    
    try:
        # Check if current account is authorized
        is_authorized = blockchain_service.is_manufacturer_authorized(blockchain_service.account.address)
        if not is_authorized:
            print(f"❌ Account {blockchain_service.account.address} is not authorized to register products")
            print("💡 You need to authorize this manufacturer first using the admin function")
            return
        
        # Test product registration
        test_product = {
            'serial_number': f'TEST{int(time.time())}',  # Unique serial
            'name': 'Test Product',
            'category': 'Electronics'
        }
        
        print(f"Attempting to register product: {test_product['serial_number']}")
        result = blockchain_service.register_product_on_blockchain(
            test_product['serial_number'],
            test_product['name'],
            test_product['category'],
            blockchain_service.account.address
        )
        
        if result and result.get('success'):
            print(f"✅ Product registered successfully!")
            print(f"Transaction hash: {result['tx_hash']}")
            print(f"Block number: {result['block_number']}")
        else:
            print(f"❌ Registration failed: {result}")
            
    except Exception as e:
        print(f"❌ Registration test failed: {e}")

def main():
    """Run all tests"""
    print("🧪 Blockchain Integration Tests")
    print("=" * 50)
    
    # Test connection first
    if not test_blockchain_connection():
        print("❌ Cannot proceed with other tests - blockchain connection failed")
        print("\n💡 Check your .env file configuration:")
        print(f"BLOCKCHAIN_RPC_URL: {os.getenv('BLOCKCHAIN_RPC_URL', 'Not set')}")
        print(f"CONTRACT_ADDRESS: {os.getenv('CONTRACT_ADDRESS', 'Not set')}")
        print(f"PRIVATE_KEY: {'Set' if os.getenv('PRIVATE_KEY') else 'Not set'}")
        return
    
    # Run other tests
    test_product_verification()
    test_manufacturer_authorization()
    # test_product_registration()  # Uncomment when ready to test registration

if __name__ == "__main__":
    import time
    main()