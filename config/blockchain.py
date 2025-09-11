# config/blockchain.py
import os
from web3 import Web3
from eth_account import Account
import json

class BlockchainConfig:
    """Blockchain configuration and connection management"""
    
    def __init__(self):
        self.rpc_url = os.getenv('BLOCKCHAIN_RPC_URL', 'https://sepolia.infura.io/v3/your-project-id')
        self.contract_address = os.getenv('CONTRACT_ADDRESS', '0x07c05F17f53ff83d0b5F469bFA0Cb36bDc9eA950')
        self.chain_id = int(os.getenv('CHAIN_ID', '11155111'))
        self.account_address = os.getenv('ACCOUNT_ADDRESS')
        self.private_key = os.getenv('PRIVATE_KEY')
        
        self.w3 = None
        self.contract = None
        self.account = None
    
    def connect(self):
        """Initialize Web3 connection"""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            if not self.w3.is_connected():
                raise Exception("Failed to connect to blockchain network")
            
            # Load contract ABI
            contract_abi_path = os.getenv('CONTRACT_ABI_PATH', 'contracts/abi.json')
            if os.path.exists(contract_abi_path):
                with open(contract_abi_path, 'r') as f:
                    contract_abi = json.load(f)
                
                self.contract = self.w3.eth.contract(
                    address=self.contract_address,
                    abi=contract_abi
                )
            
            # Load account if private key provided
            if self.private_key:
                self.account = Account.from_key(self.private_key)
            
            print(f"Connected to blockchain network (Chain ID: {self.chain_id})")
            return self.w3
            
        except Exception as e:
            print(f"Blockchain connection error: {e}")
            return None
    
    def get_web3(self):
        """Get Web3 instance"""
        if not self.w3:
            self.connect()
        return self.w3
    
    def get_contract(self):
        """Get contract instance"""
        if not self.contract:
            self.connect()
        return self.contract
    
    def get_account(self):
        """Get account for transactions"""
        return self.account
    
    def is_connected(self):
        """Check if connected to blockchain"""
        return self.w3 and self.w3.is_connected()
    
    def get_network_info(self):
        """Get network information"""
        if not self.w3:
            return None
        
        try:
            latest_block = self.w3.eth.get_block('latest')
            return {
                'chain_id': self.chain_id,
                'latest_block': latest_block.number,
                'network_name': self.get_network_name(),
                'contract_address': self.contract_address,
                'is_connected': self.is_connected()
            }
        except Exception as e:
            print(f"Error getting network info: {e}")
            return None
    
    def get_network_name(self):
        """Get human-readable network name"""
        network_names = {
            1: 'Ethereum Mainnet',
            3: 'Ropsten Testnet',
            4: 'Rinkeby Testnet',
            5: 'Goerli Testnet',
            11155111: 'Sepolia Testnet',
            137: 'Polygon Mainnet',
            80001: 'Polygon Mumbai',
            56: 'BSC Mainnet',
            97: 'BSC Testnet'
        }
        return network_names.get(self.chain_id, f'Unknown Network (Chain ID: {self.chain_id})')

# Global blockchain instance
blockchain_config = BlockchainConfig()

def get_blockchain_connection():
    """Get blockchain connection"""
    return blockchain_config.connect()

def get_web3():
    """Get Web3 instance"""
    return blockchain_config.get_web3()

def get_contract():
    """Get smart contract instance"""
    return blockchain_config.get_contract()