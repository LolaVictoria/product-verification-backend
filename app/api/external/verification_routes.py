"""
External Product Verification API
Public API for verifying products via API key authentication
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging

from app.services.verification.verification_service import verification_service
from app.services.manufacturer.account_service import account_service
from app.services.manufacturer.product_service import product_service
from app.validators.product_validator import ProductValidator
from app.api.middleware.auth_middleware import auth_middleware
from app.api.middleware.rate_limiting import api_rate_limit

logger = logging.getLogger(__name__)

verification_api_bp = Blueprint('verification_api', __name__, url_prefix='/api/external')


# ===============================
# VERIFICATION ENDPOINTS
# ===============================

@verification_api_bp.route('/verify', methods=['POST'])
@api_rate_limit({'per_minute': 100, 'per_hour': 1000})
@auth_middleware.api_key_required
def api_verify_product():
    """API endpoint for product verification"""
    try:
        data = request.get_json()
        
        if not data or not data.get('serial_number'):
            return jsonify({
                'success': False,
                'error': 'Serial number is required'
            }), 400
        
        serial_number = data['serial_number']
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        result = verification_service.verify_product(
            serial_number=serial_number,
            customer_id=None,
            user_role='api',
            user_ip=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'serial_number': serial_number,
            'verification': result,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"API verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Verification failed'
        }), 500


@verification_api_bp.route('/verify/batch', methods=['POST'])
@api_rate_limit({'per_minute': 50, 'per_hour': 500})
@auth_middleware.api_key_required
def api_verify_batch():
    """API endpoint for batch product verification"""
    try:
        data = request.get_json()
        
        if not data or not data.get('serial_numbers'):
            return jsonify({
                'success': False,
                'error': 'serial_numbers array is required'
            }), 400
        
        serial_numbers = data['serial_numbers']
        
        if not isinstance(serial_numbers, list):
            return jsonify({
                'success': False,
                'error': 'serial_numbers must be an array'
            }), 400
        
        if len(serial_numbers) > 100:
            return jsonify({
                'success': False,
                'error': 'Maximum 100 serial numbers per batch'
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        results = verification_service.verify_batch(
            serial_numbers=serial_numbers,
            customer_id=None,
            user_role='api',
            user_ip=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'batch_size': len(serial_numbers),
            'results': results,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"API batch verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Batch verification failed'
        }), 500


# ===============================
# PRODUCT MANAGEMENT (API KEY)
# ===============================

@verification_api_bp.route('/products', methods=['GET'])
@api_rate_limit({'per_minute': 60, 'per_hour': 600})
@auth_middleware.api_key_required
def api_get_products():
    """API endpoint to get manufacturer's products"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        search = request.args.get('search', '')
        
        result = product_service.get_manufacturer_products(
            manufacturer_id=manufacturer_id,
            page=page,
            limit=limit,
            search=search
        )
        
        return jsonify({
            'success': True,
            'products': result.get('products', []),
            'pagination': result.get('pagination', {}),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"API get products error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get products'
        }), 500


@verification_api_bp.route('/products/<serial_number>', methods=['GET'])
@api_rate_limit({'per_minute': 100, 'per_hour': 1000})
@auth_middleware.api_key_required
def api_get_product(serial_number):
    """API endpoint to get specific product details"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        product = product_service.get_product_by_serial(serial_number, manufacturer_id)
        
        if not product:
            return jsonify({
                'success': False,
                'error': 'Product not found or access denied'
            }), 404
        
        return jsonify({
            'success': True,
            'product': product,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"API get product error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get product'
        }), 500


@verification_api_bp.route('/products/register', methods=['POST'])
@api_rate_limit({'per_minute': 30, 'per_hour': 300})
@auth_middleware.api_key_required
def api_register_product():
    """API endpoint for product registration"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Product data is required'
            }), 400
        
        # Validate product data
        validation_result = ProductValidator.validate_product_data(data)
        if not validation_result['valid']:
            return jsonify({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        result = product_service.register_product(manufacturer_id, data)
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Product registered successfully',
                'product_id': result['product_id'],
                'serial_number': result['serial_number'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Registration failed')
            }), 400
        
    except Exception as e:
        logger.error(f"API registration error: {e}")
        return jsonify({
            'success': False,
            'error': 'Registration failed'
        }), 500


@verification_api_bp.route('/products/transfer', methods=['POST'])
@api_rate_limit({'per_minute': 20, 'per_hour': 200})
@auth_middleware.api_key_required
def api_transfer_ownership():
    """API endpoint for ownership transfer"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Transfer data is required'
            }), 400
        
        # Validate transfer data
        validation_result = ProductValidator.validate_ownership_transfer(data)
        if not validation_result['valid']:
            return jsonify({
                'success': False,
                'error': 'Validation failed',
                'errors': validation_result['errors']
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        result = product_service.transfer_ownership(manufacturer_id, data)
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Ownership transferred successfully',
                'transfer_id': result.get('transfer_id'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Transfer failed')
            }), 400
        
    except Exception as e:
        logger.error(f"API ownership transfer error: {e}")
        return jsonify({
            'success': False,
            'error': 'Ownership transfer failed'
        }), 500


# ===============================
# ANALYTICS
# ===============================

@verification_api_bp.route('/analytics', methods=['GET'])
@api_rate_limit({'per_minute': 30, 'per_hour': 300})
@auth_middleware.api_key_required
def api_get_analytics():
    """API endpoint for manufacturer analytics"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        time_range = request.args.get('time_range', '7d')
        
        from app.services.manufacturer.analytics_service import analytics_service
        result = analytics_service.get_manufacturer_overview(manufacturer_id, time_range)
        
        return jsonify({
            'success': True,
            'analytics': result,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"API analytics error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get analytics'
        }), 500


# ===============================
# CONNECTION TESTING
# ===============================

@verification_api_bp.route('/test-connection', methods=['GET'])
@auth_middleware.api_key_required
def test_connection():
    """Test API connection and authentication"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        api_key_info = request.api_key_data
        
        return jsonify({
            'success': True,
            'message': 'Connection successful',
            'manufacturer_id': manufacturer_id,
            'permissions': api_key_info.get('permissions', []),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Test connection error: {e}")
        return jsonify({
            'success': False,
            'error': 'Connection test failed'
        }), 500


# ===============================
# STATUS & HEALTH
# ===============================

@verification_api_bp.route('/status', methods=['GET'])
def api_status():
    """API status endpoint (public)"""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'endpoints': {
            'verify': '/api/external/verify',
            'verify_batch': '/api/external/verify/batch',
            'register': '/api/external/products/register',
            'products': '/api/external/products',
            'analytics': '/api/external/analytics'
        }
    }), 200


@verification_api_bp.route('/health', methods=['GET'])
def api_health():
    """API health check endpoint (public)"""
    try:
        from app.config.database import get_db_connection
        
        # Test database connection
        db = get_db_connection()
        db.command('ping')
        db_healthy = True
        
        health_status = {
            'status': 'healthy' if db_healthy else 'degraded',
            'database': 'connected' if db_healthy else 'disconnected',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return jsonify(health_status), status_code
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': 'Health check failed',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503


# ===============================
# ERROR HANDLERS
# ===============================

@verification_api_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': 'Bad request'
    }), 400


@verification_api_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'success': False,
        'error': 'Unauthorized - Valid API key required'
    }), 401


@verification_api_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404


@verification_api_bp.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded'
    }), 429


@verification_api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500