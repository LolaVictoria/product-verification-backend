from flask import Blueprint, request, jsonify
from services.crypto_service import crypto_service
from model.product import create_manufacturer_with_crypto, register_product_with_signature, verify_product_cryptographic
from middleware.auth_middleware import AuthMiddleware
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
crypto_bp = Blueprint('crypto', __name__)

@crypto_bp.route('/manufacturers/create-crypto', methods=['POST'])
@AuthMiddleware.token_required_with_roles(['admin'])
def create_crypto_manufacturer(user_id, user_role):
    """Create manufacturer with cryptographic capabilities"""
    try:
        data = request.get_json()
        
        required_fields = ['manufacturer_id', 'company_name', 'contact_email', 'wallet_address']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Add the admin user who created this manufacturer
        data['created_by'] = user_id
        
        result = create_manufacturer_with_crypto(data)
        
        return jsonify({
            'success': True,
            'manufacturer_id': result['manufacturer_id'],
            'public_key': result['public_key'],
            'key_id': result['key_id'],
            'message': 'Manufacturer created with cryptographic keys'
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating crypto manufacturer: {e}")
        return jsonify({'error': str(e)}), 500

@crypto_bp.route('/products/register-crypto', methods=['POST'])
@AuthMiddleware.token_required_with_roles(['manufacturer'])
def register_crypto_product(user_id, user_role):
    """Register product with digital signature"""
    try:
        data = request.get_json()
        
        # Get manufacturer info from user_id
        from utils.database import get_db_connection
        db = get_db_connection()
        
        # Find manufacturer associated with this user
        manufacturer = db.manufacturers.find_one({'created_by': user_id})
        if not manufacturer:
            return jsonify({'error': 'Manufacturer account not found'}), 404
        
        manufacturer_id = manufacturer['manufacturer_id']
        
        required_fields = ['serial_number', 'product_name', 'manufacturer_name', 'brand', 'model']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Add manufacturing date if not provided
        if 'manufacturing_date' not in data:
            data['manufacturing_date'] = datetime.now().isoformat()
        
        product_id = register_product_with_signature(data, manufacturer_id)
        
        return jsonify({
            'success': True,
            'product_id': product_id,
            'serial_number': data['serial_number'],
            'verification_type': 'cryptographic',
            'message': 'Product registered with digital signature'
        }), 201
        
    except Exception as e:
        logger.error(f"Error registering crypto product: {e}")
        return jsonify({'error': str(e)}), 500

@crypto_bp.route('/verify/crypto/<serial_number>', methods=['GET'])
def verify_crypto_product(serial_number):
    """Verify product using cryptographic signature - Public endpoint"""
    try:
        result = verify_product_cryptographic(serial_number)
        
        return jsonify({
            'valid': result['valid'],
            'verification_method': result.get('verification_method'),
            'product': result.get('product'),
            'reason': result.get('reason'),
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error verifying crypto product: {e}")
        return jsonify({'error': str(e)}), 500

@crypto_bp.route('/transfer/create-hash', methods=['POST'])
@AuthMiddleware.token_required_with_roles(['manufacturer', 'admin'])
def create_transfer_hash(user_id, user_role):
    """Create cryptographic hash for ownership transfer"""
    try:
        data = request.get_json()
        
        required_fields = ['serial_number', 'from_email', 'to_email']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        hash_data = crypto_service.create_transfer_hash(data)
        
        return jsonify({
            'success': True,
            'transfer_hash': hash_data['transfer_hash'],
            'message_data': hash_data['message_data']
        }), 200
        
    except Exception as e:
        logger.error(f"Error creating transfer hash: {e}")
        return jsonify({'error': str(e)}), 500

@crypto_bp.route('/manufacturer/profile', methods=['GET'])
@AuthMiddleware.token_required_with_roles(['manufacturer'])
def get_manufacturer_crypto_profile(user_id, user_role):
    """Get manufacturer crypto profile"""
    try:
        from utils.database import get_db_connection
        db = get_db_connection()
        
        # Find manufacturer associated with this user
        manufacturer = db.manufacturers.find_one({'created_by': user_id})
        if not manufacturer:
            return jsonify({'error': 'Manufacturer account not found'}), 404
        
        # Count products
        product_count = db.products.count_documents({
            'manufacturer_id': manufacturer['manufacturer_id']
        })
        
        # Count cryptographic products
        crypto_count = db.products.count_documents({
            'manufacturer_id': manufacturer['manufacturer_id'],
            'verification_type': 'cryptographic'
        })
        
        # Count verifications
        verification_count = db.verifications.count_documents({
            'product_info.manufacturer_id': manufacturer['manufacturer_id']
        })
        
        return jsonify({
            'success': True,
            'data': {
                'id': manufacturer['manufacturer_id'],
                'company_name': manufacturer['company_name'],
                'verification_status': manufacturer.get('verification_status', 'verified'),
                'crypto_enabled': manufacturer.get('crypto_enabled', False),
                'public_key': manufacturer.get('public_key', ''),
                'key_id': manufacturer.get('key_id', ''),
                'total_products': product_count,
                'crypto_products': crypto_count,
                'total_verifications': verification_count
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting manufacturer profile: {e}")
        return jsonify({'error': str(e)}), 500