from flask import Blueprint, request, jsonify
from models import Product
from utils.decorators import require_api_key
from utils.validators import validate_serial_number, validate_bulk_serial_numbers
from utils.helpers import create_error_response
import logging

logger = logging.getLogger(__name__)

verification_bp = Blueprint('verification', __name__)

@verification_bp.route('/verify/<serial_number>', methods=['GET'])
@require_api_key
def verify_product(serial_number):
    """Verify a single product by serial number"""
    try:
        if not validate_serial_number(serial_number):
            return create_error_response('Invalid serial number format')
        
        # Verify on blockchain
        from app import blockchain_service
        blockchain_result = blockchain_service.verify_product(serial_number)
        
        if not blockchain_result['verified']:
            return jsonify({
                'verified': False,
                'serial_number': serial_number,
                'message': 'Product not found or not verified'
            }), 200
        
        # Get additional data from MongoDB
        product_doc = Product.find_by_serial_number(serial_number)
        
        response_data = {
            'verified': True,
            'product': {
                'serial_number': serial_number,
                'product_name': blockchain_result['product_name'],
                'category': blockchain_result['category'],
                'manufacturer_address': blockchain_result['manufacturer'],
                'registered_at': blockchain_result['registered_at'],
                'description': product_doc.get('description', '') if product_doc else ''
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Product verification error: {e}")
        return create_error_response('Internal server error', 500)

@verification_bp.route('/verify-bulk', methods=['POST'])
@require_api_key
def verify_products_bulk():
    """Verify multiple products in a single request"""
    try:
        data = request.get_json()
        if not data:
            return create_error_response('No data provided')
        
        serial_numbers = data.get('serial_numbers', [])
        
        # Validate serial numbers
        is_valid, error_msg = validate_bulk_serial_numbers(serial_numbers)
        if not is_valid:
            return create_error_response(error_msg)
        
        # Verify on blockchain
        from app import blockchain_service
        blockchain_results = blockchain_service.verify_products_bulk(serial_numbers)
        
        results = []
        verified_count = 0
        
        for blockchain_result in blockchain_results:
            serial_number = blockchain_result['serial_number']
            
            if blockchain_result['verified']:
                verified_count += 1
                
                # Get additional data from MongoDB
                product_doc = Product.find_by_serial_number(serial_number)
                
                results.append({
                    'serial_number': serial_number,
                    'verified': True,
                    'product': {
                        'product_name': blockchain_result['product_name'],
                        'category': blockchain_result['category'],
                        'manufacturer_address': blockchain_result['manufacturer'],
                        'registered_at': blockchain_result['registered_at'],
                        'description': product_doc.get('description', '') if product_doc else ''
                    }
                })
            else:
                results.append({
                    'serial_number': serial_number,
                    'verified': False,
                    'error': blockchain_result.get('error')
                })
        
        return jsonify({
            'results': results,
            'total_checked': len(serial_numbers),
            'verified_count': verified_count,
            'success_rate': f"{(verified_count / len(serial_numbers) * 100):.1f}%"
        }), 200
        
    except Exception as e:
        logger.error(f"Bulk verification error: {e}")
        return create_error_response('Internal server error', 500)

@verification_bp.route('/verify-batch', methods=['POST'])
@require_api_key
def verify_products_batch():
    """Verify products with detailed response including timing"""
    try:
        import time
        start_time = time.time()
        
        data = request.get_json()
        if not data:
            return create_error_response('No data provided')
        
        serial_numbers = data.get('serial_numbers', [])
        include_timing = data.get('include_timing', False)
        
        # Validate serial numbers
        is_valid, error_msg = validate_bulk_serial_numbers(serial_numbers, max_count=50)  # Lower limit for batch
        if not is_valid:
            return create_error_response(error_msg)
        
        results = []
        verified_count = 0
        blockchain_time = 0
        database_time = 0
        
        from app import blockchain_service
        
        for serial_number in serial_numbers:
            try:
                # Time blockchain verification
                bc_start = time.time()
                blockchain_result = blockchain_service.verify_product(serial_number)
                bc_end = time.time()
                blockchain_time += (bc_end - bc_start)
                
                if blockchain_result['verified']:
                    verified_count += 1
                    
                    # Time database lookup
                    db_start = time.time()
                    product_doc = Product.find_by_serial_number(serial_number)
                    db_end = time.time()
                    database_time += (db_end - db_start)
                    
                    result = {
                        'serial_number': serial_number,
                        'verified': True,
                        'product': {
                            'product_name': blockchain_result['product_name'],
                            'category': blockchain_result['category'],
                            'manufacturer_address': blockchain_result['manufacturer'],
                            'registered_at': blockchain_result['registered_at'],
                            'description': product_doc.get('description', '') if product_doc else ''
                        }
                    }
                    
                    if include_timing:
                        result['verification_time_ms'] = round((bc_end - bc_start) * 1000, 2)
                        result['database_time_ms'] = round((db_end - db_start) * 1000, 2)
                    
                    results.append(result)
                else:
                    results.append({
                        'serial_number': serial_number,
                        'verified': False,
                        'error': blockchain_result.get('error')
                    })
                    
            except Exception as e:
                logger.error(f"Batch verification error for {serial_number}: {e}")
                results.append({
                    'serial_number': serial_number,
                    'verified': False,
                    'error': 'Verification failed'
                })
        
        end_time = time.time()
        total_time = end_time - start_time
        
        response = {
            'results': results,
            'total_checked': len(serial_numbers),
            'verified_count': verified_count,
            'success_rate': f"{(verified_count / len(serial_numbers) * 100):.1f}%"
        }
        
        if include_timing:
            response['timing'] = {
                'total_time_ms': round(total_time * 1000, 2),
                'blockchain_time_ms': round(blockchain_time * 1000, 2),
                'database_time_ms': round(database_time * 1000, 2),
                'average_per_product_ms': round((total_time / len(serial_numbers)) * 1000, 2)
            }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Batch verification error: {e}")
        return create_error_response('Internal server error', 500)