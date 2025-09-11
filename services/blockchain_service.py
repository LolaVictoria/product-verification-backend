# services/blockchain_service.py
import json
import os
from web3 import Web3
from eth_account import Account
from datetime import datetime, timezone
import hashlib

from utils.helper_functions import get_db_connection, get_current_utc

class BlockchainService:
    """Service for blockchain interactions"""
    
    def __init__(self):
        self.rpc_url = os.getenv('BLOCKCHAIN_RPC_URL')
        self.contract_address = os.getenv('CONTRACT_ADDRESS')
        self.private_key = os.getenv('PRIVATE_KEY')
        self.chain_id = int(os.getenv('CHAIN_ID', '11155111'))  # Default to Sepolia
        
        # Initialize Web3
        self.w3 = None
        self.contract = None
        self.account = None
        
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            if self.private_key:
                self.account = Account.from_key(self.private_key)
            
            # Load contract ABI
            contract_abi_path = os.getenv('CONTRACT_ABI_PATH')
            if contract_abi_path and os.path.exists(contract_abi_path):
                with open(contract_abi_path, 'r') as f:
                    contract_abi = json.load(f)
                    
                if self.contract_address:
                    self.contract = self.w3.eth.contract(
                        address=Web3.to_checksum_address(self.contract_address),
                        abi=contract_abi
                    )
        except Exception as e:
            print(f"Blockchain initialization error: {e}")
    
    def is_connected(self):
        """Check if blockchain connection is available"""
        try:
            return self.w3 and self.w3.is_connected()
        except:
            return False
    
    def register_product_on_blockchain(self, product_data):
        """Register product on blockchain"""
        try:
            if not self.is_connected() or not self.contract or not self.account:
                return {
                    'success': False,
                    'message': 'Blockchain connection not available'
                }
            
            # Prepare transaction data
            serial_number = product_data['serial_number']
            manufacturer_address = Web3.to_checksum_address(product_data['manufacturer_wallet'])
            product_hash = self._generate_product_hash(product_data)
            
            # Build transaction
            function_call = self.contract.functions.registerProduct(
                serial_number,
                manufacturer_address,
                product_hash,
                product_data.get('name', ''),
                product_data.get('category', '')
            )
            
            # Estimate gas
            try:
                gas_estimate = function_call.estimate_gas({
                    'from': self.account.address
                })
                gas_limit = int(gas_estimate * 1.2)  # Add 20% buffer
            except Exception as e:
                print(f"Gas estimation failed: {e}")
                gas_limit = 300000  # Default gas limit
            
            # Get current gas price
            gas_price = self.w3.eth.gas_price
            
            # Build transaction
            transaction = function_call.build_transaction({
                'from': self.account.address,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'chainId': self.chain_id
            })
            
            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(
                transaction, private_key=self.private_key
            )
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            # Wait for confirmation (with timeout)
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                if receipt.status == 1:  # Success
                    # Store transaction details
                    self._store_blockchain_transaction(
                        serial_number, tx_hash_hex, receipt, product_data
                    )
                    
                    return {
                        'success': True,
                        'transaction_hash': tx_hash_hex,
                        'block_number': receipt.blockNumber,
                        'gas_used': receipt.gasUsed,
                        'contract_address': self.contract_address
                    }
                else:
                    return {
                        'success': False,
                        'message': 'Transaction failed',
                        'transaction_hash': tx_hash_hex
                    }
                    
            except Exception as e:
                print(f"Transaction confirmation error: {e}")
                return {
                    'success': False,
                    'message': 'Transaction timeout or confirmation failed',
                    'transaction_hash': tx_hash_hex
                }
                
        except Exception as e:
            print(f"Blockchain registration error: {e}")
            return {
                'success': False,
                'message': f'Blockchain registration failed: {str(e)}'
            }
    
    def verify_product_on_blockchain(self, serial_number):
        """Verify product exists on blockchain"""
        try:
            if not self.is_connected() or not self.contract:
                return {
                    'verified': False,
                    'error': 'Blockchain connection not available'
                }
            
            # Call contract function to check product
            try:
                result = self.contract.functions.getProduct(serial_number).call()
                
                # Assuming contract returns: (manufacturer, productHash, timestamp, isActive)
                if result and len(result) >= 4:
                    manufacturer_address, product_hash, timestamp, is_active = result[:4]
                    
                    if is_active and manufacturer_address != '0x0000000000000000000000000000000000000000':
                        return {
                            'verified': True,
                            'manufacturer_address': manufacturer_address,
                            'product_hash': product_hash,
                            'registered_timestamp': timestamp,
                            'contract_address': self.contract_address
                        }
                
                return {'verified': False, 'error': 'Product not found on blockchain'}
                
            except Exception as e:
                print(f"Contract call error: {e}")
                return {'verified': False, 'error': f'Contract verification failed: {str(e)}'}
                
        except Exception as e:
            print(f"Blockchain verification error: {e}")
            return {'verified': False, 'error': f'Blockchain verification failed: {str(e)}'}
    
    def transfer_product_ownership(self, serial_number, from_address, to_address, transfer_data):
        """Transfer product ownership on blockchain"""
        try:
            if not self.is_connected() or not self.contract or not self.account:
                return {
                    'success': False,
                    'message': 'Blockchain connection not available'
                }
            
            from_address = Web3.to_checksum_address(from_address)
            to_address = Web3.to_checksum_address(to_address)
            
            # Build transfer transaction
            function_call = self.contract.functions.transferOwnership(
                serial_number,
                from_address,
                to_address,
                transfer_data.get('sale_price', 0),
                transfer_data.get('notes', '')
            )
            
            # Estimate gas
            try:
                gas_estimate = function_call.estimate_gas({
                    'from': self.account.address
                })
                gas_limit = int(gas_estimate * 1.2)
            except Exception as e:
                print(f"Gas estimation failed: {e}")
                gas_limit = 200000
            
            # Build transaction
            transaction = function_call.build_transaction({
                'from': self.account.address,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'chainId': self.chain_id
            })
            
            # Sign and send
            signed_txn = self.w3.eth.account.sign_transaction(
                transaction, private_key=self.private_key
            )
            
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if receipt.status == 1:
                return {
                    'success': True,
                    'transaction_hash': tx_hash_hex,
                    'block_number': receipt.blockNumber,
                    'gas_used': receipt.gasUsed
                }
            else:
                return {
                    'success': False,
                    'message': 'Transfer transaction failed',
                    'transaction_hash': tx_hash_hex
                }
                
        except Exception as e:
            print(f"Ownership transfer error: {e}")
            return {
                'success': False,
                'message': f'Ownership transfer failed: {str(e)}'
            }
    
    def get_product_history(self, serial_number):
        """Get product ownership history from blockchain"""
        try:
            if not self.is_connected() or not self.contract:
                return {
                    'success': False,
                    'message': 'Blockchain connection not available'
                }
            
            # Get transfer events for this product
            try:
                # Filter for transfer events
                event_filter = self.contract.events.OwnershipTransferred.create_filter(
                    fromBlock=0,
                    argument_filters={'serialNumber': serial_number}
                )
                
                events = event_filter.get_all_entries()
                
                history = []
                for event in events:
                    history.append({
                        'transaction_hash': event.transactionHash.hex(),
                        'block_number': event.blockNumber,
                        'from_address': event.args.from_,
                        'to_address': event.args.to,
                        'sale_price': event.args.get('salePrice', 0),
                        'timestamp': event.args.get('timestamp', 0),
                        'notes': event.args.get('notes', '')
                    })
                
                return {
                    'success': True,
                    'history': history
                }
                
            except Exception as e:
                print(f"Event filtering error: {e}")
                return {
                    'success': False,
                    'message': f'Failed to retrieve history: {str(e)}'
                }
                
        except Exception as e:
            print(f"History retrieval error: {e}")
            return {
                'success': False,
                'message': f'History retrieval failed: {str(e)}'
            }
    
    def verify_manufacturer_on_blockchain(self, manufacturer_address):
        """Verify manufacturer is registered on blockchain"""
        try:
            if not self.is_connected() or not self.contract:
                return {
                    'verified': False,
                    'error': 'Blockchain connection not available'
                }
            
            manufacturer_address = Web3.to_checksum_address(manufacturer_address)
            
            # Call contract to check manufacturer
            try:
                result = self.contract.functions.isVerifiedManufacturer(manufacturer_address).call()
                
                return {
                    'verified': result,
                    'manufacturer_address': manufacturer_address
                }
                
            except Exception as e:
                print(f"Manufacturer verification error: {e}")
                return {
                    'verified': False,
                    'error': f'Manufacturer verification failed: {str(e)}'
                }
                
        except Exception as e:
            print(f"Manufacturer blockchain verification error: {e}")
            return {
                'verified': False,
                'error': f'Verification failed: {str(e)}'
            }
    
    def get_blockchain_stats(self):
        """Get blockchain statistics"""
        try:
            if not self.is_connected():
                return {
                    'success': False,
                    'message': 'Blockchain connection not available'
                }
            
            stats = {
                'network': self._get_network_name(),
                'block_number': self.w3.eth.block_number,
                'gas_price': self.w3.eth.gas_price,
                'connected': True
            }
            
            if self.contract:
                try:
                    # Get contract stats if available
                    total_products = self.contract.functions.getTotalProducts().call()
                    stats['total_products_on_chain'] = total_products
                except:
                    pass
            
            return {
                'success': True,
                'stats': stats
            }
            
        except Exception as e:
            print(f"Blockchain stats error: {e}")
            return {
                'success': False,
                'message': f'Failed to retrieve stats: {str(e)}'
            }
    
    def _generate_product_hash(self, product_data):
        """Generate product hash for blockchain storage"""
        hash_data = {
            'serial_number': product_data['serial_number'],
            'brand': product_data.get('brand', ''),
            'model': product_data.get('model', ''),
            'device_type': product_data.get('device_type', ''),
            'manufacturer': product_data.get('manufacturer_name', ''),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def _store_blockchain_transaction(self, serial_number, tx_hash, receipt, product_data):
        """Store blockchain transaction details in database"""
        try:
            db = get_db_connection()
            
            transaction_record = {
                'serial_number': serial_number,
                'transaction_hash': tx_hash,
                'block_number': receipt.blockNumber,
                'gas_used': receipt.gasUsed,
                'gas_price': receipt.gasPrice if hasattr(receipt, 'gasPrice') else None,
                'contract_address': self.contract_address,
                'transaction_type': 'product_registration',
                'product_data': product_data,
                'timestamp': get_current_utc(),
                'status': 'confirmed'
            }
            
            db.blockchain_transactions.insert_one(transaction_record)
            
        except Exception as e:
            print(f"Transaction storage error: {e}")
    
    def _get_network_name(self):
        """Get network name based on chain ID"""
        network_names = {
            1: 'mainnet',
            3: 'ropsten',
            4: 'rinkeby',
            5: 'goerli',
            11155111: 'sepolia',
            137: 'polygon',
            80001: 'mumbai',
            56: 'bsc',
            97: 'bsc_testnet'
        }
        return network_names.get(self.chain_id, f'unknown_chain_{self.chain_id}')

# Global blockchain service instance
blockchain_service = BlockchainService()