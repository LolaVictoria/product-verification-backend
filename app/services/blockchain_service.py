#services/blockchain_service
import os
import json
import hashlib
from web3 import Web3
from eth_account import Account
import logging

logger = logging.getLogger(__name__)

class BlockchainService:
    def __init__(self):
        self.rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
        self.contract_address = os.getenv('CONTRACT_ADDRESS')
        self.private_key = os.getenv('PRIVATE_KEY')
        self.chain_id = int(os.getenv('CHAIN_ID', '11155111'))
        
        self.web3 = None
        self.contract = None
        self.account = None
        self.connected = False
        
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize blockchain connection"""
        try:
            if not self.rpc_url:
                logger.warning("BLOCKCHAIN_RPC_URL not configured")
                return
            
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            if not self.web3.is_connected():
                logger.error("Failed to connect to blockchain network")
                return
            
            # Load contract ABI
            contract_abi = self._get_contract_abi()
            if self.contract_address and contract_abi:
                self.contract = self.web3.eth.contract(
                    address=Web3.to_checksum_address(self.contract_address),
                    abi=contract_abi
                )
            
            # Load account for transactions
            if self.private_key:
                self.account = Account.from_key(self.private_key)
            
            self.connected = True
            logger.info(f"Connected to blockchain network (Chain ID: {self.chain_id})")
            
        except Exception as e:
            logger.error(f"Blockchain initialization failed: {e}")
            self.connected = False
    
    def _get_contract_abi(self):
        """Get contract ABI"""
        abi_json = '''[
            {
                "inputs": [
                    {"name": "_serialNumber", "type": "string"},
                    {"name": "_brand", "type": "string"},
                    {"name": "_model", "type": "string"},
                    {"name": "_deviceType", "type": "string"},
                    {"name": "_storage", "type": "string"},
                    {"name": "_color", "type": "string"},
                    {"name": "_batchNumber", "type": "string"},
                    {"name": "_specHash", "type": "string"}
                ],
                "name": "registerDevice",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "_serialNumber", "type": "string"}],
                "name": "verifyDevice",
                "outputs": [
                    {"name": "exists", "type": "bool"},
                    {"name": "isAuthentic", "type": "bool"},
                    {"name": "brand", "type": "string"},
                    {"name": "model", "type": "string"},
                    {"name": "deviceType", "type": "string"},
                    {"name": "manufacturerName", "type": "string"},
                    {"name": "currentOwner", "type": "address"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "_serialNumber", "type": "string"}],
                "name": "getDeviceDetails",
                "outputs": [
                    {"name": "brand", "type": "string"},
                    {"name": "model", "type": "string"},
                    {"name": "deviceType", "type": "string"},
                    {"name": "storageData", "type": "string"},
                    {"name": "color", "type": "string"},
                    {"name": "manufacturerName", "type": "string"},
                    {"name": "currentOwner", "type": "address"},
                    {"name": "manufacturingDate", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "_serialNumber", "type": "string"}],
                "name": "getOwnershipHistory",
                "outputs": [
                    {"name": "previousOwners", "type": "address[]"},
                    {"name": "newOwners", "type": "address[]"},
                    {"name": "transferDates", "type": "uint256[]"},
                    {"name": "transferReasons", "type": "string[]"},
                    {"name": "salePrices", "type": "uint256[]"}
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ]'''
        return json.loads(abi_json)
    
    def is_connected(self):
        """Check if blockchain connection is active"""
        return self.connected and self.web3 and self.web3.is_connected()
    
    def register_device(self, serial_number, device_data):
        """Register device on blockchain"""
        if not self.is_connected() or not self.contract or not self.account:
            return {
                'success': False,
                'error': 'Blockchain not connected or account not configured'
            }
        
        try:
            # Generate specification hash
            spec_string = f"{device_data.get('brand', '')}{device_data.get('model', '')}{serial_number}"
            spec_hash = hashlib.sha256(spec_string.encode()).hexdigest()
            
            # Build transaction
            transaction = self.contract.functions.registerDevice(
                serial_number,
                device_data.get('brand', ''),
                device_data.get('model', ''),
                device_data.get('device_type', ''),
                device_data.get('storage_data', ''),
                device_data.get('color', ''),
                device_data.get('batch_number', ''),
                f"0x{spec_hash[:32]}"
            ).build_transaction({
                'from': self.account.address,
                'gas': 300000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
                'chainId': self.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            return {
                'success': True,
                'transaction_hash': receipt.transactionHash.hex(),
                'block_number': receipt.blockNumber,
                'gas_used': receipt.gasUsed,
                'status': receipt.status
            }
            
        except Exception as e:
            logger.error(f"Blockchain registration error: {e}")
            return {
                'success': False,
                'error': f'Failed to register on blockchain: {str(e)}'
            }
    
    def verify_device(self, serial_number):
        """Verify device on blockchain"""
        if not self.is_connected() or not self.contract:
            return {
                'verified': False,
                'error': 'Blockchain not connected'
            }
        
        try:
            # Call contract function
            result = self.contract.functions.verifyDevice(serial_number).call()
            
            # Unpack result tuple
            if len(result) >= 7:
                exists, is_authentic, brand, model, device_type, manufacturer_name, current_owner = result[:7]
                
                if exists and is_authentic:
                    return {
                        'verified': True,
                        'blockchain_data': {
                            'exists': exists,
                            'is_authentic': is_authentic,
                            'brand': brand,
                            'model': model,
                            'device_type': device_type,
                            'manufacturer_name': manufacturer_name,
                            'current_owner': current_owner
                        },
                        'contract_address': self.contract_address,
                        'network': self._get_network_name()
                    }
                else:
                    return {
                        'verified': False,
                        'error': f'Device not found or not authentic. Exists: {exists}, Authentic: {is_authentic}'
                    }
            else:
                return {
                    'verified': False,
                    'error': f'Unexpected contract response: {result}'
                }
                
        except Exception as e:
            logger.error(f"Blockchain verification error: {e}")
            return {
                'verified': False,
                'error': f'Verification failed: {str(e)}'
            }
    
    def get_device_details(self, serial_number):
        """Get detailed device information from blockchain"""
        if not self.is_connected() or not self.contract:
            return {'success': False, 'error': 'Blockchain not connected'}
        
        try:
            result = self.contract.functions.getDeviceDetails(serial_number).call()
            
            # Unpack result
            brand, model, device_type, storage_data, color, manufacturer_name, current_owner, manufacturing_date = result
            
            return {
                'success': True,
                'data': {
                    'brand': brand,
                    'model': model,
                    'device_type': device_type,
                    'storage_data': storage_data,
                    'color': color,
                    'manufacturer_name': manufacturer_name,
                    'current_owner': current_owner,
                    'manufacturing_date': manufacturing_date
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting device details: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_ownership_history(self, serial_number):
        """Get ownership history from blockchain"""
        if not self.is_connected() or not self.contract:
            return {'success': False, 'error': 'Blockchain not connected'}
        
        try:
            result = self.contract.functions.getOwnershipHistory(serial_number).call()
            
            # Unpack result
            previous_owners, new_owners, transfer_dates, transfer_reasons, sale_prices = result
            
            history = []
            for i in range(len(previous_owners)):
                history.append({
                    'previous_owner': previous_owners[i],
                    'new_owner': new_owners[i],
                    'transfer_date': transfer_dates[i],
                    'transfer_reason': transfer_reasons[i],
                    'sale_price': sale_prices[i]
                })
            
            return {'success': True, 'history': history}
            
        except Exception as e:
            logger.error(f"Error getting ownership history: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_network_info(self):
        """Get network information"""
        if not self.is_connected():
            return None
        
        try:
            latest_block = self.web3.eth.get_block('latest')
            return {
                'chain_id': self.chain_id,
                'latest_block': latest_block.number,
                'network_name': self._get_network_name(),
                'contract_address': self.contract_address,
                'connected': True
            }
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return None
    
    def _get_network_name(self):
        """Get human-readable network name"""
        network_names = {
            1: 'Ethereum Mainnet',
            5: 'Goerli Testnet',
            11155111: 'Sepolia Testnet',
            137: 'Polygon Mainnet',
            80001: 'Polygon Mumbai'
        }
        return network_names.get(self.chain_id, f'Unknown Network (Chain ID: {self.chain_id})')
    
    def estimate_gas(self, function_call):
        """Estimate gas for a transaction"""
        if not self.is_connected() or not self.account:
            return None
        
        try:
            return function_call.estimate_gas({'from': self.account.address})
        except Exception as e:
            logger.error(f"Gas estimation error: {e}")
            return None
    
    def get_transaction_receipt(self, tx_hash):
        """Get transaction receipt"""
        if not self.is_connected():
            return None
        
        try:
            return self.web3.eth.get_transaction_receipt(tx_hash)
        except Exception as e:
            logger.error(f"Error getting transaction receipt: {e}")
            return None


blockchain_service = BlockchainService()