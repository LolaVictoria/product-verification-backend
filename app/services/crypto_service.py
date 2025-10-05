#services/crypto_service
import os
import json
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import logging

logger = logging.getLogger(__name__)

class CryptoService:
    def __init__(self):
        # Load or generate master encryption key for storing private keys
        self.master_key = self._get_or_create_master_key()
        self.cipher_suite = Fernet(self.master_key)
    
    @staticmethod
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

crypto_service = CryptoService()