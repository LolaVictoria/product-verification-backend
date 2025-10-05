# services/signature_verification_service.py - MISSING FROM YOUR CODE
"""
Cryptographic signature verification for product authenticity
This is what actually makes your verification secure
"""
import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64
import logging
from app.config.database import get_db_connection
logger = logging.getLogger(__name__)

class SignatureVerificationService:
    """Core cryptographic verification logic"""
    
    def __init__(self):
        self.signature_algorithm = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    
    def create_product_signature(self, product_data: dict, manufacturer_private_key: str) -> dict:
        """Create cryptographic signature for product registration"""
        try:
            # Create canonical product data for signing
            canonical_data = self._create_canonical_product_data(product_data)
            
            # Load manufacturer's private key
            private_key = serialization.load_pem_private_key(
                manufacturer_private_key.encode(),
                password=None
            )
            
            # Create signature
            message = canonical_data.encode('utf-8')
            signature = private_key.sign(message, self.signature_algorithm, hashes.SHA256())
            
            # Create verification data
            return {
                'product_signature': base64.b64encode(signature).decode(),
                'signed_data': canonical_data,
                'signature_timestamp': datetime.utcnow().isoformat(),
                'signature_algorithm': 'RSA-PSS-SHA256',
                'manufacturer_public_key_hash': self._get_public_key_hash(private_key.public_key())
            }
            
        except Exception as e:
            logger.error(f"Failed to create product signature: {e}")
            raise
    
    def verify_product_signature(self, serial_number: str, signature_data: dict, 
                                manufacturer_public_key: str) -> dict:
        """Verify product authenticity using cryptographic signature"""
        try:
            # Load manufacturer's public key
            public_key = serialization.load_pem_public_key(manufacturer_public_key.encode())
            
            # Decode signature
            signature = base64.b64decode(signature_data['product_signature'])
            
            # Verify signature
            message = signature_data['signed_data'].encode('utf-8')
            
            try:
                public_key.verify(signature, message, self.signature_algorithm, hashes.SHA256())
                
                # Parse signed data to verify product details
                signed_product_data = json.loads(signature_data['signed_data'])
                
                # Verify serial number matches
                if signed_product_data.get('serial_number') != serial_number:
                    return {
                        'verified': False,
                        'reason': 'Serial number mismatch',
                        'expected': signed_product_data.get('serial_number'),
                        'provided': serial_number
                    }
                
                return {
                    'verified': True,
                    'product_data': signed_product_data,
                    'signature_verified': True,
                    'manufacturer_verified': True,
                    'verification_method': 'cryptographic_signature',
                    'signature_timestamp': signature_data.get('signature_timestamp'),
                    'verified_at': datetime.utcnow().isoformat()
                }
                
            except InvalidSignature:
                return {
                    'verified': False,
                    'reason': 'Invalid cryptographic signature',
                    'signature_verified': False,
                    'manufacturer_verified': False
                }
                
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return {
                'verified': False,
                'reason': f'Verification error: {str(e)}',
                'error': True
            }
    
    def _create_canonical_product_data(self, product_data: dict) -> str:
        """Create canonical representation of product data for signing"""
        # Extract essential fields in consistent order
        canonical = {
            'serial_number': product_data['serial_number'],
            'brand': product_data.get('brand', ''),
            'model': product_data.get('model', ''),
            'device_type': product_data.get('device_type', ''),
            'manufacturing_date': product_data.get('manufacturing_date', ''),
            'manufacturer_name': product_data.get('manufacturer_name', ''),
            'batch_number': product_data.get('batch_number', ''),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Create deterministic JSON string (sorted keys)
        return json.dumps(canonical, sort_keys=True, separators=(',', ':'))
    
    def _get_public_key_hash(self, public_key) -> str:
        """Get hash of public key for identification"""
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_key_bytes).hexdigest()[:16]

signature_service = SignatureVerificationService()