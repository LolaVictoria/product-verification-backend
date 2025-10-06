"""
External Blockchain/Crypto API
Blockchain verification and cryptographic operations
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging

from app.services.crypto_service import crypto_service
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.rate_limiting import api_rate_limit

logger = logging.getLogger(__name__)

crypto_bp = Blueprint('crypto', __name__, url_prefix='/external/crypto')


@crypto_bp.route('/manufacturers/create', methods=['POST'])
@auth_middleware.token_required_with_roles(['admin'])
@api_rate_limit({'per_minute': 10, 'per_hour': 50})
def create_crypto_manufacturer(current_user_id, current_user_role):
    """Create manufacturer with cryptographic capabilities (admin only)"""
    try:
        data = request.get_json()
        
        required_fields = ['manufacturer_id', 'company_name', 'contact_email', 'wallet_address']
        missing_fields = [f for f in required_fields if f not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        data['created_by'] = current_user_id
        
        result = crypto_service.create_manufacturer_with_crypto(data)
        
        return jsonify({
            'success': True,
            'manufacturer_id': result['manufacturer_id'],
            'public_key': result['public_key'],
            'key_id': result['key_id'],
            'message': 'Manufacturer created with cryptographic keys'
        }), 201
        
    except Exception as e:
        logger.error(f"Create crypto manufacturer error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create manufacturer'
        }), 500


@crypto_bp.route('/products/register', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer'])
@api_rate_limit({'per_minute': 30, 'per_hour': 300})
def register_crypto_product(current_user_id, current_user_role):
    """Register product with digital signature"""
    try:
        data = request.get_json()
        
        required_fields = ['serial_number', 'product_name', 'manufacturer_name', 'brand', 'model']
        missing_fields = [f for f in required_fields if f not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Get manufacturer ID from current user
        from app.config.database import get_db_connection
        db = get_db_connection()
        manufacturer = db.manufacturers.find_one({'created_by': current_user_id})
        
        if not manufacturer:
            return jsonify({
                'success': False,
                'error': 'Manufacturer account not found'
            }), 404
        
        manufacturer_id = manufacturer['manufacturer_id']
        
        if 'manufacturing_date' not in data:
            data['manufacturing_date'] = datetime.now(timezone.utc).isoformat()
        
        result = crypto_service.register_product_with_signature(data, manufacturer_id)
        
        return jsonify({
            'success': True,
            'product_id': result['product_id'],
            'serial_number': data['serial_number'],
            'verification_type': 'cryptographic',
            'message': 'Product registered with digital signature'
        }), 201
        
    except Exception as e:
        logger.error(f"Register crypto product error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to register product'
        }), 500


@crypto_bp.route('/verify/<serial_number>', methods=['GET'])
@api_rate_limit({'per_minute': 100, 'per_hour': 1000})
def verify_crypto_product(serial_number):
    """Verify product using cryptographic signature (public endpoint)"""
    try:
        result = crypto_service.verify_product_cryptographic(serial_number)
        
        return jsonify({
            'success': True,
            'valid': result.get('valid', False),
            'verification_method': result.get('verification_method'),
            'product': result.get('product'),
            'reason': result.get('reason'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Verify crypto product error: {e}")
        return jsonify({
            'success': False,
            'error': 'Verification failed'
        }), 500


@crypto_bp.route('/transfer/create-hash', methods=['POST'])
@auth_middleware.token_required_with_roles(['manufacturer', 'admin'])
@api_rate_limit({'per_minute': 20, 'per_hour': 200})
def create_transfer_hash(current_user_id, current_user_role):
    """Create cryptographic hash for ownership transfer"""
    try:
        data = request.get_json()
        
        required_fields = ['serial_number', 'from_email', 'to_email']
        missing_fields = [f for f in required_fields if f not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        hash_data = crypto_service.create_transfer_hash(data)
        
        return jsonify({
            'success': True,
            'transfer_hash': hash_data['transfer_hash'],
            'message_data': hash_data['message_data']
        }), 200
        
    except Exception as e:
        logger.error(f"Create transfer hash error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create transfer hash'
        }), 500


@crypto_bp.route('/manufacturer/profile', methods=['GET'])
@auth_middleware.token_required_with_roles(['manufacturer'])
def get_manufacturer_crypto_profile(current_user_id, current_user_role):
    """Get manufacturer crypto profile"""
    try:
        from app.config.database import get_db_connection
        db = get_db_connection()
        
        manufacturer = db.manufacturers.find_one({'created_by': current_user_id})
        
        if not manufacturer:
            return jsonify({
                'success': False,
                'error': 'Manufacturer account not found'
            }), 404
        
        manufacturer_id = manufacturer['manufacturer_id']
        
        # Get counts
        product_count = db.products.count_documents({'manufacturer_id': manufacturer_id})
        crypto_count = db.products.count_documents({
            'manufacturer_id': manufacturer_id,
            'verification_type': 'cryptographic'
        })
        verification_count = db.verifications.count_documents({
            'product_info.manufacturer_id': manufacturer_id
        })
        
        return jsonify({
            'success': True,
            'data': {
                'id': manufacturer_id,
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
        logger.error(f"Get manufacturer profile error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get profile'
        }), 500