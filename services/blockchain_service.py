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

    # new update
    # Add these methods to your existing BlockchainService class

def batch_authorize_manufacturers(self, wallet_addresses, owner_address=None):
    """Authorize multiple manufacturers in a single transaction (saves gas)"""
    if not self.contract:
        return {'success': False, 'error': 'Contract not initialized'}
        
    try:
        if not wallet_addresses:
            return {'success': False, 'error': 'No wallet addresses provided'}
        
        # Use configured owner or first available account
        if not owner_address:
            owner_address = getattr(Config, 'OWNER_ADDRESS', None)
            if not owner_address:
                accounts = self.w3.eth.accounts
                if not accounts:
                    return {'success': False, 'error': 'No owner account available'}
                owner_address = accounts[0]
        
        # Convert all addresses to checksum format
        try:
            owner_address = Web3.to_checksum_address(owner_address)
            wallet_addresses = [Web3.to_checksum_address(addr) for addr in wallet_addresses]
        except Exception as e:
            return {'success': False, 'error': f'Invalid address format: {e}'}
        
        # Check if we can access the owner account
        if owner_address not in self.w3.eth.accounts:
            return {
                'success': False,
                'error': f'Cannot access owner account {owner_address}. Private key not available.'
            }
        
        # Estimate gas for batch operation
        gas_estimate = self.contract.functions.batchAuthorizeManufacturers(wallet_addresses).estimate_gas({
            'from': owner_address
        })
        
        # Execute batch authorization
        tx_hash = self.contract.functions.batchAuthorizeManufacturers(wallet_addresses).transact({
            'from': owner_address,
            'gas': int(gas_estimate * 1.2)  # Add 20% buffer
        })
        
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            'success': True,
            'tx_hash': tx_hash.hex(),
            'receipt': receipt,
            'authorized_addresses': wallet_addresses,
            'gas_used': receipt.gasUsed,
            'gas_saved_vs_individual': f"~{len(wallet_addresses) * 21000 - receipt.gasUsed} gas"
        }
        
    except Exception as e:
        logger.error(f"Batch manufacturer authorization failed: {e}")
        return {'success': False, 'error': str(e)}

def verify_manufacturer_authorization(self, wallet_address):
    """Check if a manufacturer is authorized on the blockchain"""
    if not self.contract:
        return {'authorized': False, 'error': 'Contract not initialized'}
        
    try:
        wallet_address = Web3.to_checksum_address(wallet_address)
        
        # Call the smart contract to check authorization
        is_authorized = self.contract.functions.isManufacturerAuthorized(wallet_address).call()
        
        return {
            'authorized': is_authorized,
            'wallet_address': wallet_address
        }
        
    except Exception as e:
        logger.error(f"Manufacturer authorization check failed: {e}")
        return {'authorized': False, 'error': str(e)}

def get_gas_price_estimate(self):
    """Get current gas price for cost estimation"""
    try:
        gas_price = self.w3.eth.gas_price
        return {
            'gas_price_wei': gas_price,
            'gas_price_gwei': self.w3.from_wei(gas_price, 'gwei'),
            'estimated_cost_usd': self.estimate_transaction_cost_usd(gas_price)
        }
    except Exception as e:
        logger.error(f"Gas price estimation failed: {e}")
        return {'error': str(e)}

def estimate_transaction_cost_usd(self, gas_price, gas_limit=50000, eth_price_usd=2000):
    """Estimate transaction cost in USD (you can get real ETH price from an API)"""
    try:
        cost_eth = self.w3.from_wei(gas_price * gas_limit, 'ether')
        cost_usd = float(cost_eth) * eth_price_usd
        return round(cost_usd, 4)
    except:
        return 0