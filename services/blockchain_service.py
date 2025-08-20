
import logging
from config import Config

logger = logging.getLogger(__name__)

class BlockchainService:
    """Service for blockchain integration with Web3"""
    
    def __init__(self, provider_url=None, contract_address=None, contract_abi_path=None):
        # Use config values if not provided
        self.provider_url = provider_url or getattr(Config, 'BLOCKCHAIN_RPC_URL', None)
        self.contract_address = contract_address or getattr(Config, 'CONTRACT_ADDRESS', None)
        self.contract_abi_path = contract_abi_path or getattr(Config, 'CONTRACT_ABI_PATH', None)
        
        # Initialize Web3
        if self.provider_url:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.provider_url))
                
                if not self.w3.is_connected():
                    logger.warning("Cannot connect to blockchain provider")
                    self.w3 = None
                else:
                    self._load_contract()
            except Exception as e:
                logger.error(f"Blockchain initialization failed: {e}")
                self.w3 = None
                self.contract = None
        else:
            logger.info("No blockchain provider URL configured - using mock mode")
            self.w3 = None
            self.contract = None
    
    def _load_contract(self):
        """Load contract ABI and initialize contract"""
        if not self.contract_abi_path or not os.path.exists(self.contract_abi_path):
            logger.warning(f"Contract ABI file not found at: {self.contract_abi_path}")
            self.contract = None
            return
        
        try:
            with open(self.contract_abi_path, 'r') as f:
                abi_data = json.load(f)
                
                # Handle different ABI file formats
                if isinstance(abi_data, list):
                    self.contract_abi = abi_data
                elif isinstance(abi_data, dict):
                    if 'abi' in abi_data:
                        self.contract_abi = abi_data['abi']
                    elif 'contracts' in abi_data:
                        # Truffle/Hardhat format
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
        
            # Initialize contract
            if self.contract_address and self.w3:
                self.contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(self.contract_address),
                    abi=self.contract_abi
                )
            else:
                self.contract = None
                
        except Exception as e:
            logger.error(f"Error loading contract: {e}")
            self.contract = None
    
    def is_connected(self):
        """Check if connected to blockchain"""
        try:
            return self.w3.is_connected() if self.w3 else False
        except Exception:
            return False
    
    @staticmethod
    def get_instance():
        """Get singleton instance of BlockchainService"""
        if not hasattr(BlockchainService, '_instance'):
            BlockchainService._instance = BlockchainService()
        return BlockchainService._instance
    
    def batch_authorize_manufacturers(self, wallet_addresses, owner_address=None):
        """Batch authorize manufacturers in a single transaction"""
        if not self.is_connected() or not self.contract:
            # Fallback to mock mode
            return self._mock_batch_authorize(wallet_addresses)
        
        try:
            if not wallet_addresses:
                return {'success': False, 'error': 'No wallet addresses provided'}
            
            # Use configured owner or environment variable
            if not owner_address:
                owner_address = getattr(Config, 'ADMIN_WALLET_ADDRESS', None)
                if not owner_address:
                    accounts = self.w3.eth.accounts
                    if not accounts:
                        return {'success': False, 'error': 'No owner account available'}
                    owner_address = accounts[0]
            
            # Convert addresses to checksum format
            try:
                owner_address = Web3.to_checksum_address(owner_address)
                wallet_addresses = [Web3.to_checksum_address(addr) for addr in wallet_addresses]
            except Exception as e:
                return {'success': False, 'error': f'Invalid address format: {e}'}
            
            # Estimate gas for batch operation
            gas_estimate = self.contract.functions.batchAuthorizeManufacturers(
                wallet_addresses
            ).estimate_gas({'from': owner_address})
            
            # Execute batch authorization
            tx_hash = self.contract.functions.batchAuthorizeManufacturers(
                wallet_addresses
            ).transact({
                'from': owner_address,
                'gas': int(gas_estimate * 1.2)  # Add 20% buffer
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'gas_used': str(receipt.gasUsed),
                'authorized_count': len(wallet_addresses),
                'authorized_addresses': wallet_addresses
            }
            
        except Exception as e:
            logger.error(f"Batch authorization failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _mock_batch_authorize(self, wallet_addresses):
        """Mock batch authorization for development/testing"""
        try:
            tx_hash = f"0x{''.join([f'{ord(c):02x}' for c in str(int(time.time()))])}"
            gas_used = str(50000 + len(wallet_addresses) * 30000)
            
            logger.info(f"Mock: Authorized {len(wallet_addresses)} manufacturers")
            
            return {
                'success': True,
                'tx_hash': tx_hash,
                'gas_used': gas_used,
                'authorized_count': len(wallet_addresses),
                'authorized_addresses': wallet_addresses
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def verify_manufacturer_authorization(self, wallet_address):
        """Check if a manufacturer is authorized on blockchain"""
        if not self.is_connected() or not self.contract:
            # Mock mode - return True for development
            return {'authorized': True, 'wallet_address': wallet_address}
        
        try:
            wallet_address = Web3.to_checksum_address(wallet_address)
            is_authorized = self.contract.functions.isManufacturerAuthorized(wallet_address).call()
            
            return {
                'authorized': is_authorized,
                'wallet_address': wallet_address
            }
            
        except Exception as e:
            logger.error(f"Authorization check failed: {e}")
            return {'authorized': False, 'error': str(e)}
    
    def batch_verify_manufacturers(self, wallet_addresses):
        """Verify multiple manufacturer authorizations at once"""
        if not self.is_connected() or not self.contract:
            # Mock mode
            return {
                'success': True,
                'results': [
                    {'address': addr, 'authorized': True} 
                    for addr in wallet_addresses
                ],
                'total_checked': len(wallet_addresses),
                'authorized_count': len(wallet_addresses)
            }
        
        try:
            results = []
            
            for address in wallet_addresses:
                try:
                    address = Web3.to_checksum_address(address)
                    is_authorized = self.contract.functions.isManufacturerAuthorized(address).call()
                    
                    results.append({
                        'address': address,
                        'authorized': is_authorized
                    })
                    
                except Exception as e:
                    logger.error(f"Error verifying {address}: {e}")
                    results.append({
                        'address': address,
                        'authorized': False,
                        'error': str(e)
                    })
            
            return {
                'success': True,
                'results': results,
                'total_checked': len(wallet_addresses),
                'authorized_count': sum(1 for r in results if r.get('authorized', False))
            }
            
        except Exception as e:
            logger.error(f"Batch verification failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def revoke_manufacturer_authorization(self, wallet_address, owner_address=None):
        """Revoke authorization for a manufacturer"""
        if not self.is_connected() or not self.contract:
            # Mock mode
            return {
                'success': True,
                'tx_hash': f"0x{''.join([f'{ord(c):02x}' for c in str(int(time.time()))])}",
                'gas_used': '30000',
                'revoked_address': wallet_address
            }
        
        try:
            if not owner_address:
                owner_address = getattr(Config, 'ADMIN_WALLET_ADDRESS', None)
                if not owner_address:
                    accounts = self.w3.eth.accounts
                    if not accounts:
                        return {'success': False, 'error': 'No owner account available'}
                    owner_address = accounts[0]
            
            # Validate addresses
            owner_address = Web3.to_checksum_address(owner_address)
            wallet_address = Web3.to_checksum_address(wallet_address)
            
            # Check if manufacturer is currently authorized
            is_authorized = self.contract.functions.isManufacturerAuthorized(wallet_address).call()
            if not is_authorized:
                return {'success': False, 'error': 'Manufacturer is not currently authorized'}
            
            # Execute revocation
            gas_estimate = self.contract.functions.revokeManufacturer(wallet_address).estimate_gas({
                'from': owner_address
            })
            
            tx_hash = self.contract.functions.revokeManufacturer(wallet_address).transact({
                'from': owner_address,
                'gas': int(gas_estimate * 1.2)
            })
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'gas_used': str(receipt.gasUsed),
                'revoked_address': wallet_address,
                'revoked_by': owner_address
            }
            
        except Exception as e:
            logger.error(f"Authorization revocation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_gas_price_estimate(self):
        """Get current gas price for cost estimation"""
        if not self.is_connected():
            return {
                'gas_price_wei': 20000000000,  # 20 gwei mock
                'gas_price_gwei': 20,
                'estimated_cost_usd': 5.0
            }
        
        try:
            gas_price = self.w3.eth.gas_price
            return {
                'gas_price_wei': gas_price,
                'gas_price_gwei': self.w3.from_wei(gas_price, 'gwei'),
                'estimated_cost_usd': self._estimate_transaction_cost_usd(gas_price)
            }
        except Exception as e:
            logger.error(f"Gas price estimation failed: {e}")
            return {'error': str(e)}
    
    def _estimate_transaction_cost_usd(self, gas_price, gas_limit=50000, eth_price_usd=2000):
        """Estimate transaction cost in USD"""
        try:
            cost_eth = self.w3.from_wei(gas_price * gas_limit, 'ether')
            cost_usd = float(cost_eth) * eth_price_usd
            return round(cost_usd, 4)
        except:
            return 0
    
    def estimate_batch_authorization_cost(self, wallet_addresses_count):
        """Estimate the cost of batch authorizing manufacturers"""
        if not self.is_connected():
            return {
                'success': True,
                'estimated_gas': 50000 + (wallet_addresses_count * 30000),
                'gas_price_gwei': 20,
                'cost_eth': 0.005,
                'cost_usd': 10.0,
                'manufacturers_count': wallet_addresses_count
            }
        
        try:
            gas_price = self.w3.eth.gas_price
            
            # Estimate gas for batch operation
            base_gas = 50000
            gas_per_address = 30000
            estimated_gas = base_gas + (gas_per_address * wallet_addresses_count)
            
            cost_wei = gas_price * estimated_gas
            cost_eth = self.w3.from_wei(cost_wei, 'ether')
            
            eth_price_usd = 2000  # You might want to get this from an API
            cost_usd = float(cost_eth) * eth_price_usd
            
            return {
                'success': True,
                'estimated_gas': estimated_gas,
                'gas_price_gwei': self.w3.from_wei(gas_price, 'gwei'),
                'cost_eth': float(cost_eth),
                'cost_usd': round(cost_usd, 4),
                'manufacturers_count': wallet_addresses_count
            }
            
        except Exception as e:
            logger.error(f"Cost estimation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_contract_stats(self):
        """Get general statistics about the smart contract"""
        if not self.is_connected() or not self.contract:
            return {
                'success': True,
                'stats': {
                    'contract_address': 'Not configured',
                    'is_connected': False,
                    'mode': 'Mock/Development',
                    'total_authorized_manufacturers': 0
                }
            }
        
        try:
            stats = {
                'contract_address': self.contract_address,
                'is_connected': self.is_connected(),
                'mode': 'Production'
            }
            
            try:
                owner = self.contract.functions.owner().call()
                stats['owner'] = owner
            except:
                stats['owner'] = 'Unknown'
            
            try:
                # Get latest block info
                latest_block = self.w3.eth.get_block('latest')
                stats['latest_block_number'] = latest_block.number
                stats['latest_block_timestamp'] = latest_block.timestamp
            except:
                pass
            
            return {'success': True, 'stats': stats}
            
        except Exception as e:
            logger.error(f"Failed to get contract stats: {e}")
            return {'success': False, 'error': str(e)}

# Static methods for backward compatibility
def authorize_manufacturers_on_blockchain(wallet_addresses):
    """Backward compatibility function"""
    service = BlockchainService.get_instance()
    return service.batch_authorize_manufacturers(wallet_addresses)