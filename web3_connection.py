# Update your web3_connection.py to match the fixed loading logic
import json
from web3 import Web3
from config import Config

w3 = None
contract = None
account = None

if Config.PROVIDER_URL:
    w3 = Web3(Web3.HTTPProvider(Config.PROVIDER_URL))
    if not w3.is_connected():
        raise RuntimeError("Cannot connect to provider")
    
    if Config.CONTRACT_ABI_PATH and Config.CONTRACT_ADDRESS:
        with open(Config.CONTRACT_ABI_PATH, "r") as f:
            abi_data = json.load(f)
            # Use the same ABI loading logic as BlockchainService
            if isinstance(abi_data, list):
                abi = abi_data
            elif isinstance(abi_data, dict) and 'abi' in abi_data:
                abi = abi_data['abi']
            else:
                raise ValueError("Unknown ABI format")
        
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(Config.CONTRACT_ADDRESS), 
            abi=abi
        )
    
    if Config.PRIVATE_KEY:
        account = w3.eth.account.from_key(Config.PRIVATE_KEY)