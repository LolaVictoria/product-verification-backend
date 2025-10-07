#services/crypto_service
import os
import json
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import logging
from typing import Dict, Any
from bson import ObjectId
logger = logging.getLogger(__name__)

class CryptoService:
    def __init__(self):
        # Load or generate master encryption key for storing private keys
        self.master_key = self._get_or_create_master_key()
        self.cipher_suite = Fernet(self.master_key)
    
    def _get_or_create_master_key(self):
        """Get or create master encryption key for private key storage"""
        key_file = 'crypto_master.key'
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new master key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            logger.info("Generated new master encryption key")
            return key
    
    @staticmethod
    def generate_manufacturer_keypair(self):
        """Generate RSA key pair for manufacturer"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Encrypt private key for storage
            encrypted_private_key = self.cipher_suite.encrypt(private_key_pem)
            
            return {
                'public_key': public_key_pem.decode('utf-8'),
                'encrypted_private_key': base64.b64encode(encrypted_private_key).decode('utf-8'),
                'key_id': self._generate_key_id(public_key_pem)
            }
            
        except Exception as e:
            logger.error(f"Error generating keypair: {e}")
            raise
    
    @staticmethod
    def _generate_key_id(self, public_key_pem):
        """Generate unique ID for key pair"""
        return hashlib.sha256(public_key_pem).hexdigest()[:16]
    
    @staticmethod
    def create_product_signature(self, encrypted_private_key_b64, product_data):
        """Create digital signature for product registration"""
        try:
            # Decrypt private key
            encrypted_private_key = base64.b64decode(encrypted_private_key_b64)
            private_key_pem = self.cipher_suite.decrypt(encrypted_private_key)
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            # Create message to sign
            message_data = {
                'serial_number': product_data['serial_number'],
                'product_name': product_data['product_name'],
                'manufacturer_name': product_data['manufacturer_name'],
                'manufacturing_date': product_data['manufacturing_date'],
                'timestamp': datetime.now().isoformat()
            }
            
            # Convert to canonical JSON string
            message = json.dumps(message_data, sort_keys=True).encode('utf-8')
            
            # Create signature
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return {
                'signature': base64.b64encode(signature).decode('utf-8'),
                'message_data': message_data,
                'signature_algorithm': 'RSA-PSS-SHA256'
            }
            
        except Exception as e:
            logger.error(f"Error creating signature: {e}")
            raise
    
    @staticmethod
    def verify_product_signature(self, public_key_pem, signature_b64, message_data):
        """Verify product signature"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            
            # Reconstruct message
            message = json.dumps(message_data, sort_keys=True).encode('utf-8')
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    @staticmethod
    def create_transfer_hash(self, transfer_data):
        """Create cryptographic hash for ownership transfer"""
        try:
            # Create transfer message
            message_data = {
                'serial_number': transfer_data['serial_number'],
                'from_email': transfer_data['from_email'],
                'to_email': transfer_data['to_email'],
                'timestamp': datetime.now().isoformat(),
                'nonce': os.urandom(16).hex()  # Random nonce for uniqueness
            }
            
            # Create hash
            message = json.dumps(message_data, sort_keys=True).encode('utf-8')
            hash_digest = hashlib.sha256(message).hexdigest()
            
            return {
                'transfer_hash': hash_digest,
                'message_data': message_data
            }
            
        except Exception as e:
            logger.error(f"Error creating transfer hash: {e}")
            raise

    @staticmethod
    def get_manufacturer_details(self, manufacturer_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific manufacturer
        
        Args:
            manufacturer_id: The manufacturer's user ID
            
        Returns:
            Dict with detailed manufacturer information
        """
        try:
            # Get manufacturer from users collection
            manufacturer = self.db.users.find_one(
                {'_id': ObjectId(manufacturer_id), 'role': 'manufacturer'}
            )
            
            if not manufacturer:
                raise Exception("Manufacturer not found")
            
            # Get product statistics
            total_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_id
            })
            
            crypto_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_id,
                'registration_type': 'cryptographic'
            })
            
            blockchain_products = total_products - crypto_products
            
            # Get recent products
            recent_products = list(self.db.products.find(
                {'manufacturer_id': manufacturer_id}
            ).sort('created_at', -1).limit(5))
            
            # Get verification statistics
            total_verifications = self.db.verifications.count_documents({
                'manufacturer_id': manufacturer_id
            })
            
            # Get recent verifications
            recent_verifications = list(self.db.verifications.find(
                {'manufacturer_id': manufacturer_id}
            ).sort('verified_at', -1).limit(10))
            
            # Format response
            return {
                'success': True,
                'manufacturer': {
                    'id': str(manufacturer['_id']),
                    'company_name': manufacturer.get('current_company_name', 'N/A'),
                    'contact_email': manufacturer.get('primary_email', 'N/A'),
                    'phone': manufacturer.get('phone_number'),
                    'address': manufacturer.get('company_address'),
                    'verification_status': manufacturer.get('verification_status', 'pending'),
                    'account_status': manufacturer.get('account_status', 'active'),
                    'crypto_enabled': manufacturer.get('crypto_enabled', False),
                    'public_key_id': manufacturer.get('public_key_id'),
                    'wallet_addresses': manufacturer.get('wallet_addresses', []),
                    'registration_date': manufacturer.get('registration_date', datetime.now(timezone.utc)).isoformat(),
                    'last_login': manufacturer.get('last_login').isoformat() if manufacturer.get('last_login') else None,
                    'email_verified': manufacturer.get('email_verified', False),
                },
                'statistics': {
                    'total_products': total_products,
                    'cryptographic_products': crypto_products,
                    'blockchain_products': blockchain_products,
                    'total_verifications': total_verifications
                },
                'recent_products': [
                    {
                        'id': str(p['_id']),
                        'serial_number': p.get('serial_number'),
                        'brand': p.get('brand'),
                        'model': p.get('model'),
                        'registration_type': p.get('registration_type'),
                        'created_at': p.get('created_at', datetime.now(timezone.utc)).isoformat()
                    }
                    for p in recent_products
                ],
                'recent_verifications': [
                    {
                        'id': str(v['_id']),
                        'serial_number': v.get('serial_number'),
                        'verified_at': v.get('verified_at', datetime.now(timezone.utc)).isoformat(),
                        'location': v.get('location', {}).get('country', 'Unknown')
                    }
                    for v in recent_verifications
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer details: {e}", exc_info=True)
            raise Exception(f"Failed to get manufacturer details: {str(e)}")
        
crypto_service = CryptoService()