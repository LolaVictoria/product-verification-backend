from web3 import Web3
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BlockchainService:
    def __init__(self, provider_url, contract_address, contract_abi_path):
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        self.contract_address = contract_address
        
        # Load contract ABI
        with open(contract_abi_path, 'r') as f:
            contract_data = json.load(f)
            self.contract_abi = contract_data[0]['abi']
        
        self.contract = self.w3.eth.contract(
            address=contract_address,
            abi=self.contract_abi
        )
    
    def is_connected(self):
        """Check if connected to blockchain"""
        try:
            return self.w3.is_connected()
        except Exception:
            return False
    
    def authorize_manufacturer(self, wallet_address, owner_address=None):
        """Authorize a manufacturer on the blockchain"""
        try:
            if not owner_address:
                owner_address = self.w3.eth.accounts[0]
            
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