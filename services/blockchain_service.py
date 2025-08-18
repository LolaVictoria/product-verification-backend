from web3 import Web3
import json
import logging
import os
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

class BlockchainService:
    def __init__(self, provider_url=None, contract_address=None, contract_abi_path=None):
        # Use config values if not provided
        self.provider_url = provider_url or Config.PROVIDER_URL
        self.contract_address = contract_address or Config.CONTRACT_ADDRESS
        self.contract_abi_path = contract_abi_path or Config.CONTRACT_ABI_PATH
        
        # Initialize Web3
        if not self.provider_url:
            raise ValueError("Provider URL is required")
        
        self.w3 = Web3(Web3.HTTPProvider(self.provider_url))
        
        if not self.w3.is_connected():
            raise RuntimeError("Cannot connect to blockchain provider")
        
        # Load contract ABI - FIX THE ABI LOADING
        if not self.contract_abi_path or not os.path.exists(self.contract_abi_path):
            raise FileNotFoundError(f"Contract ABI file not found at: {self.contract_abi_path}")
        
        try:
            with open(self.contract_abi_path, 'r') as f:
                # Load ABI directly - don't assume nested structure
                abi_data = json.load(f)
                
                # Handle different ABI file formats
                if isinstance(abi_data, list):
                    # ABI is directly an array
                    self.contract_abi = abi_data
                elif isinstance(abi_data, dict):
                    # Check common nested structures
                    if 'abi' in abi_data:
                        self.contract_abi = abi_data['abi']
                    elif 'contracts' in abi_data:
                        # Truffle/Hardhat format - take the first contract
                        contract_names = list(abi_data['contracts'].keys())
                        if contract_names:
                            first_contract = abi_data['contracts'][contract_names[0]]
                            self.contract_abi = first_contract.get('abi', [])
                        else:
                            raise ValueError("No contracts found in ABI file")
                    else:
                        raise ValueError("Unknown ABI file format")
                else:
                    raise ValueError("Invalid ABI file format")
                    
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in ABI file: {e}")
        except Exception as e:
            raise RuntimeError(f"Error loading ABI: {e}")
        
        # Initialize contract
        if not self.contract_address:
            logger.warning("No contract address provided - some functions will not work")
            self.contract = None
        else:
            try:
                self.contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(self.contract_address),
                    abi=self.contract_abi
                )
            except Exception as e:
                raise RuntimeError(f"Error initializing contract: {e}")
    
    def is_connected(self):
        """Check if connected to blockchain"""
        try:
            return self.w3.is_connected()
        except Exception:
            return False
    
    def authorize_manufacturer(self, wallet_address, owner_address=None):
        """Authorize a manufacturer on the blockchain"""
        if not self.contract:
            return {'success': False, 'error': 'Contract not initialized'}
            
        try:
            if not owner_address:
                # Use first available account or raise error
                accounts = self.w3.eth.accounts
                if not accounts:
                    return {'success': False, 'error': 'No accounts available'}
                owner_address = accounts[0]
            
            tx_hash = self.contract.functions.authorizeManufacturer(wallet_address).transact({
                'from': owner_address
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return {'success': True, 'tx_hash': tx_hash.hex(), 'receipt': receipt}
        
        except Exception as e:
            logger.error(f"Manufacturer authorization failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def register_product(self, serial_number, product_name, category, wallet_address):
        """Register a product on the blockchain"""
        if not self.contract:
            return {'success': False, 'error': 'Contract not initialized'}
            
        try:
            # Estimate gas
            gas_estimate = self.contract.functions.registerProduct(
                serial_number, product_name, category
            ).estimate_gas({'from': wallet_address})
            
            # Execute transaction
            tx_hash = self.contract.functions.registerProduct(
                serial_number, product_name, category
            ).transact({
                'from': wallet_address,
                'gas': int(gas_estimate * 1.2)
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'receipt': receipt,
                'gas_used': receipt.gasUsed
            }
        
        except Exception as e:
            logger.error(f"Product registration failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def verify_product(self, serial_number):
        """Verify a product on the blockchain"""
        if not self.contract:
            return {'verified': False, 'error': 'Contract not initialized'}
            
        try:
            result = self.contract.functions.verifyProduct(serial_number).call()
            verified, manufacturer, product_name, category, timestamp = result
            
            if verified:
                return {
                    'verified': True,
                    'manufacturer': manufacturer,
                    'product_name': product_name,
                    'category': category,
                    'timestamp': timestamp,
                    'registered_at': datetime.fromtimestamp(timestamp).isoformat()
                }
            else:
                return {'verified': False}
        
        except Exception as e:
            logger.error(f"Product verification failed: {e}")
            return {'verified': False, 'error': str(e)}
    
    def verify_products_bulk(self, serial_numbers):
        """Verify multiple products on the blockchain"""
        results = []
        
        for serial_number in serial_numbers:
            try:
                result = self.verify_product(serial_number)
                result['serial_number'] = serial_number
                results.append(result)
            except Exception as e:
                logger.error(f"Bulk verification error for {serial_number}: {e}")
                results.append({
                    'serial_number': serial_number,
                    'verified': False,
                    'error': 'Verification failed'
                })
        
        return results
    
    def get_latest_block(self):
        """Get latest block information"""
        try:
            return self.w3.eth.get_block('latest')
        except Exception as e:
            logger.error(f"Failed to get latest block: {e}")
            return None