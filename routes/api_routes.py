from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging

from services.verification_service import verification_service
from services.manufacturer_service import manufacturer_service
from middleware.auth_middleware import auth_middleware
from middleware.rate_limiting import api_rate_limit
from utils.validators import validate_product_data, validate_ownership_transfer

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

@api_bp.route('/verify', methods=['POST'])
@api_rate_limit({'per_minute': 100, 'per_hour': 1000})
@auth_middleware.api_key_required(manufacturer_service)
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
        
        # Get manufacturer info from API key
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        result = verification_service.verify_product_comprehensive(
            serial_number=serial_number,
            user_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            manufacturer_id=manufacturer_id
        )
        
        return jsonify({
            'success': True,
            'serial_number': serial_number,
            'verification_result': result,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"API verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Verification failed',
            'details': str(e)
        }), 500

@api_bp.route('/verify/batch', methods=['POST'])
@api_rate_limit({'per_minute': 50, 'per_hour': 500})
@auth_middleware.api_key_required(manufacturer_service)
def api_verify_batch():
    """API endpoint for batch product verification"""
    try:
        data = request.get_json()
        if not data or not data.get('serial_numbers'):
            return jsonify({
                'success': False,
                'error': 'Serial numbers array is required'
            }), 400
        
        serial_numbers = data['serial_numbers']
        if not isinstance(serial_numbers, list) or len(serial_numbers) > 100:
            return jsonify({
                'success': False,
                'error': 'Serial numbers must be an array with max 100 items'
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        results = verification_service.verify_batch_products(
            serial_numbers=serial_numbers,
            user_ip=request.remote_addr,
            manufacturer_id=manufacturer_id
        )
        
        return jsonify({
            'success': True,
            'batch_size': len(serial_numbers),
            'results': results,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"API batch verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Batch verification failed',
            'details': str(e)
        }), 500

@api_bp.route('/register', methods=['POST'])
@api_rate_limit({'per_minute': 30, 'per_hour': 300})
@auth_middleware.api_key_required(manufacturer_service)
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
        validation_error = validate_product_data(data)
        if validation_error:
            return jsonify({
                'success': False,
                'error': validation_error
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        # Add manufacturer ID to product data
        data['manufacturer_id'] = manufacturer_id
        
        result = manufacturer_service.register_product_via_api(data)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Product registered successfully',
                'product_id': result['product_id'],
                'serial_number': result['serial_number'],
                'registration_type': result.get('registration_type', 'database'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400
        
    except Exception as e:
        logger.error(f"API registration error: {e}")
        return jsonify({
            'success': False,
            'error': 'Registration failed',
            'details': str(e)
        }), 500

@api_bp.route('/ownership/transfer', methods=['POST'])
@api_rate_limit({'per_minute': 20, 'per_hour': 200})
@auth_middleware.api_key_required(manufacturer_service)
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
        validation_error = validate_ownership_transfer(data)
        if validation_error:
            return jsonify({
                'success': False,
                'error': validation_error
            }), 400
        
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        result = manufacturer_service.transfer_ownership_via_api(
            data, manufacturer_id
        )
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Ownership transferred successfully',
                'transfer_id': result['transfer_id'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400
        
    except Exception as e:
        logger.error(f"API ownership transfer error: {e}")
        return jsonify({
            'success': False,
            'error': 'Ownership transfer failed',
            'details': str(e)
        }), 500

@api_bp.route('/products', methods=['GET'])
@api_rate_limit({'per_minute': 60, 'per_hour': 600})
@auth_middleware.api_key_required(manufacturer_service)
def api_get_products():
    """API endpoint to get manufacturer's products"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 per page
        search = request.args.get('search', '')
        
        result = manufacturer_service.get_manufacturer_products_api(
            manufacturer_id=manufacturer_id,
            page=page,
            limit=limit,
            search=search
        )
        
        return jsonify({
            'success': True,
            'products': result['products'],
            'pagination': result['pagination'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"API get products error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get products',
            'details': str(e)
        }), 500

@api_bp.route('/products/<serial_number>', methods=['GET'])
@api_rate_limit({'per_minute': 100, 'per_hour': 1000})
@auth_middleware.api_key_required(manufacturer_service)
def api_get_product(serial_number):
    """API endpoint to get specific product details"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        product = manufacturer_service.get_product_by_serial_and_manufacturer(
            serial_number, manufacturer_id
        )
        
        if not product:
            return jsonify({
                'success': False,
                'error': 'Product not found or access denied'
            }), 404
        
        return jsonify({
            'success': True,
            'product': product,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"API get product error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get product',
            'details': str(e)
        }), 500

@api_bp.route('/analytics', methods=['GET'])
@api_rate_limit({'per_minute': 30, 'per_hour': 300})
@auth_middleware.api_key_required(manufacturer_service)
def api_get_analytics():
    """API endpoint for manufacturer analytics"""
    try:
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        time_range = request.args.get('time_range', '7d')
        
        result = manufacturer_service.get_manufacturer_analytics_api(
            manufacturer_id=manufacturer_id,
            time_range=time_range
        )
        
        return jsonify({
            'success': True,
            'analytics': result,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"API analytics error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get analytics',
            'details': str(e)
        }), 500

@api_bp.route('/webhook', methods=['POST'])
@auth_middleware.api_key_required(manufacturer_service)
def api_webhook_endpoint():
    """API webhook endpoint for receiving notifications"""
    try:
        data = request.get_json()
        manufacturer_id = request.api_key_data.get('manufacturer_id')
        
        from services.notification_service import notification_service
        result = notification_service.process_webhook(
            data=data,
            manufacturer_id=manufacturer_id,
            source_ip=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'message': 'Webhook processed successfully',
            'webhook_id': result.get('webhook_id')
        })
        
    except Exception as e:
        logger.error(f"API webhook error: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook processing failed',
            'details': str(e)
        }), 500

@api_bp.route('/status', methods=['GET'])
def api_status():
    """API status endpoint (public)"""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'endpoints': {
            'verify': '/api/v1/verify',
            'register': '/api/v1/register',
            'products': '/api/v1/products',
            'analytics': '/api/v1/analytics'
        }
    })

@api_bp.route('/health', methods=['GET'])
def api_health():
    """API health check endpoint (public)"""
    try:
        from utils.database import check_database_health
        from services.blockchain_service import blockchain_service
        
        db_healthy = check_database_health()
        blockchain_connected = blockchain_service.is_connected()
        
        health_status = {
            'status': 'healthy' if db_healthy and blockchain_connected else 'degraded',
            'database': 'connected' if db_healthy else 'disconnected',
            'blockchain': 'connected' if blockchain_connected else 'disconnected',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        
        return jsonify(health_status), status_code
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503

# Error handlers for API blueprint
@api_bp.errorhandler(400)
def api_bad_request(error):
    return jsonify({
        'success': False,
        'error': 'Bad request',
        'message': 'Invalid request data or parameters'
    }), 400

@api_bp.errorhandler(401)
def api_unauthorized(error):
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'message': 'Valid API key required'
    }), 401

@api_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'Endpoint or resource not found'
    }), 404

@api_bp.errorhandler(429)
def api_rate_limit(error):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please slow down.'
    }), 429

@api_bp.errorhandler(500)
def api_internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500