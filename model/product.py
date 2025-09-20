# In your models file
from utils.database import get_db_connection
from services.crypto_service import crypto_service
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def create_manufacturer_with_crypto(manufacturer_data):
    """Create manufacturer with cryptographic keys"""
    try:
        db = get_db_connection()
        
        # Generate cryptographic keys
        keypair = crypto_service.generate_manufacturer_keypair()
        
        manufacturer = {
            'manufacturer_id': manufacturer_data['manufacturer_id'],
            'company_name': manufacturer_data['company_name'],
            'contact_email': manufacturer_data['contact_email'],
            'wallet_address': manufacturer_data['wallet_address'],
            
            # Cryptographic fields
            'public_key': keypair['public_key'],
            'encrypted_private_key': keypair['encrypted_private_key'],
            'key_id': keypair['key_id'],
            
            'verification_status': 'verified',
            'created_at': datetime.now(),
            'crypto_enabled': True
        }
        
        result = db.manufacturers.insert_one(manufacturer)
        
        logger.info(f"Manufacturer created with crypto keys: {manufacturer_data['manufacturer_id']}")
        
        return {
            'manufacturer_id': str(result.inserted_id),
            'public_key': keypair['public_key'],
            'key_id': keypair['key_id']
        }
        
    except Exception as e:
        logger.error(f"Error creating manufacturer: {e}")
        raise

def register_product_with_signature(product_data, manufacturer_id):
    """Register product with digital signature"""
    try:
        db = get_db_connection()
        
        # Get manufacturer's encrypted private key
        manufacturer = db.manufacturers.find_one({'manufacturer_id': manufacturer_id})
        if not manufacturer:
            raise ValueError("Manufacturer not found")
        
        if not manufacturer.get('crypto_enabled'):
            raise ValueError("Manufacturer not crypto-enabled")
        
        # Create digital signature
        signature_data = crypto_service.create_product_signature(
            manufacturer['encrypted_private_key'],
            product_data
        )
        
        product = {
            'serial_number': product_data['serial_number'],
            'product_name': product_data['product_name'],
            'manufacturer_id': manufacturer_id,
            'manufacturer_name': product_data['manufacturer_name'],
            'brand': product_data['brand'],
            'model': product_data['model'],
            'manufacturing_date': product_data['manufacturing_date'],
            
            # Cryptographic fields
            'digital_signature': signature_data['signature'],
            'signature_message': signature_data['message_data'],
            'signature_algorithm': signature_data['signature_algorithm'],
            'verification_type': 'cryptographic',
            'public_key': manufacturer['public_key'],  # Reference to manufacturer's public key
            
            'created_at': datetime.now(),
            'registration_type': 'cryptographic',
            'status': 'active'
        }
        
        result = db.products.insert_one(product)
        
        logger.info(f"Product registered with signature: {product_data['serial_number']}")
        
        return str(result.inserted_id)
        
    except Exception as e:
        logger.error(f"Error registering product: {e}")
        raise

def verify_product_cryptographic(serial_number):
    """Verify product using cryptographic signature"""
    try:
        db = get_db_connection()
        
        # Get product
        product = db.products.find_one({'serial_number': serial_number})
        if not product:
            return {'valid': False, 'reason': 'product_not_found'}
        
        if product.get('verification_type') != 'cryptographic':
            return {'valid': False, 'reason': 'not_cryptographic_product'}
        
        # Verify signature
        is_valid = crypto_service.verify_product_signature(
            product['public_key'],
            product['digital_signature'],
            product['signature_message']
        )
        
        # Log verification attempt
        verification_log = {
            'serial_number': serial_number,
            'timestamp': datetime.now(),
            'result': 'valid' if is_valid else 'invalid_signature',
            'verification_method': 'cryptographic',
            'signature_algorithm': product.get('signature_algorithm', 'unknown')
        }
        
        db.verifications.insert_one(verification_log)
        
        return {
            'valid': is_valid,
            'product': product if is_valid else None,
            'verification_method': 'cryptographic'
        }
        
    except Exception as e:
        logger.error(f"Error verifying product: {e}")
        return {'valid': False, 'reason': 'verification_error', 'error': str(e)}