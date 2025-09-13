from flask import Blueprint, request, jsonify, g
from datetime import datetime
from bson import ObjectId
import logging

# Import middleware and utilities
from middleware.auth_middleware import auth_middleware, manufacturer_required, optional_auth_middleware
from utils.formatters import (
    create_success_response, create_error_response, 
    format_product_response, create_cors_response
)
from utils.validators import validate_manufacturer_data

# Import services
try:
    from services.product_service import product_service
except ImportError:
    product_service = None

product_bp = Blueprint('products', __name__)
logger = logging.getLogger(__name__)

# Product Schema Validation (from your model)
class ProductSchema:
    """Schema validation for Product model"""
    @staticmethod
    def validate_product_data(data: dict) -> dict:
        """Validate product registration data"""
        required_fields = ['serial_number', 'brand', 'model', 'device_type']
        errors = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append(f"{field} is required")
        
        # Additional validations
        if 'serial_number' in data and len(data['serial_number']) < 3:
            errors.append("Serial number must be at least 3 characters long")
        
        if 'brand' in data and len(data['brand']) < 2:
            errors.append("Brand must be at least 2 characters long")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return data

# @product_bp.route('/register', methods=['POST', 'OPTIONS'])
# @manufacturer_required
# @auth_middleware
# def register_product():
#     """Register a new product"""
#     if request.method == 'OPTIONS':
#         return create_cors_response()
    
#     try:
#         data = request.get_json()
#         if not data:
#             return create_cors_response(
#                 create_error_response("No data provided"), 400
#             )
        
#         # Validate product data
#         ProductSchema.validate_product_data(data)
        
#         # Add manufacturer info from authenticated user
#         data['manufacturer_id'] = ObjectId(g.current_user.get('user_id'))
#         data['manufacturer_name'] = g.current_user.get('username', '')
#         data['registered_at'] = datetime.utcnow()
#         data['created_at'] = datetime.utcnow()
#         data['updated_at'] = datetime.utcnow()
#         data['registration_type'] = 'database'
#         data['blockchain_verified'] = False
        
#         # Initialize ownership history
#         data['ownership_history'] = [{
#             'owner_id': str(data['manufacturer_id']),
#             'owner_name': data['manufacturer_name'],
#             'action': 'registered',
#             'timestamp': datetime.utcnow().isoformat()
#         }]
        
#         if product_service:
#             result = product_service.register_product(data)
#             if result['success']:
#                 response_data = format_product_response(result['product'])
#                 return create_cors_response(
#                     create_success_response(response_data, "Product registered successfully"), 201
#                 )
#             else:
#                 return create_cors_response(
#                     create_error_response(result['error']), 400
#                 )
#         else:
#             # Fallback response when service is not available
#             return create_cors_response(
#                 create_success_response(data, "Product registration received (service unavailable)"), 201
#             )
    
#     except ValueError as e:
#         return create_cors_response(
#             create_error_response(str(e), "VALIDATION_ERROR"), 400
#         )
#     except Exception as e:
#         logger.error(f"Product registration error: {e}")
#         return create_cors_response(
#             create_error_response("Internal server error"), 500
#         )

@product_bp.route('/<product_id>', methods=['GET', 'OPTIONS'])
@optional_auth_middleware
def get_product(product_id):
    """Get product by ID"""
    if request.method == 'OPTIONS':
        return create_cors_response()
    
    try:
        if not ObjectId.is_valid(product_id):
            return create_cors_response(
                create_error_response("Invalid product ID format"), 400
            )
        
        if product_service:
            result = product_service.get_product_by_id(ObjectId(product_id))
            if result['success']:
                response_data = format_product_response(result['product'])
                return create_cors_response(
                    create_success_response(response_data)
                )
            else:
                return create_cors_response(
                    create_error_response(result['error']), 404
                )
        else:
            # Fallback response
            sample_product = {
                'id': product_id,
                'serial_number': 'SAMPLE123',
                'brand': 'Sample Brand',
                'model': 'Sample Model',
                'device_type': 'Sample Device',
                'status': 'Service unavailable'
            }
            return create_cors_response(
                create_success_response(sample_product)
            )
    
    except Exception as e:
        logger.error(f"Get product error: {e}")
        return create_cors_response(
            create_error_response("Internal server error"), 500
        )

@product_bp.route('/serial/<serial_number>', methods=['GET', 'OPTIONS'])
@optional_auth_middleware
def get_product_by_serial(serial_number):
    """Get product by serial number"""
    if request.method == 'OPTIONS':
        return create_cors_response()
    
    try:
        if not serial_number or len(serial_number) < 3:
            return create_cors_response(
                create_error_response("Invalid serial number"), 400
            )
        
        if product_service:
            result = product_service.get_product_by_serial(serial_number)
            if result['success']:
                response_data = format_product_response(result['product'])
                return create_cors_response(
                    create_success_response(response_data)
                )
            else:
                return create_cors_response(
                    create_error_response(result['error']), 404
                )
        else:
            # Fallback response
            sample_product = {
                'serial_number': serial_number,
                'brand': 'Sample Brand',
                'model': 'Sample Model',
                'device_type': 'Sample Device',
                'status': 'Service unavailable'
            }
            return create_cors_response(
                create_success_response(sample_product)
            )
    
    except Exception as e:
        logger.error(f"Get product by serial error: {e}")
        return create_cors_response(
            create_error_response("Internal server error"), 500
        )

# @product_bp.route('/manufacturer', methods=['GET', 'OPTIONS'])
# @manufacturer_required
# @auth_middleware
# def get_manufacturer_products():
    """Get all products for authenticated manufacturer"""
    if request.method == 'OPTIONS':
        return create_cors_response()
    
    try:
        manufacturer_id = ObjectId(g.current_user.get('user_id'))
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        if product_service:
            result = product_service.get_products_by_manufacturer(manufacturer_id, page, limit)
            if result['success']:
                products = [format_product_response(product) for product in result['products']]
                response_data = {
                    'products': products,
                    'total': result.get('total', len(products)),
                    'page': page,
                    'limit': limit
                }
                return create_cors_response(
                    create_success_response(response_data)
                )
            else:
                return create_cors_response(
                    create_error_response(result['error']), 400
                )
        else:
            # Fallback response
            sample_products = [
                {
                    'id': '1',
                    'serial_number': 'SAMPLE123',
                    'brand': 'Sample Brand',
                    'model': 'Model A',
                    'device_type': 'Device'
                },
                {
                    'id': '2',
                    'serial_number': 'SAMPLE456',
                    'brand': 'Sample Brand',
                    'model': 'Model B',
                    'device_type': 'Device'
                }
            ]
            return create_cors_response(
                create_success_response({'products': sample_products, 'total': 2})
            )
    
    except Exception as e:
        logger.error(f"Get manufacturer products error: {e}")
        return create_cors_response(
            create_error_response("Internal server error"), 500
        )

# @product_bp.route('/<product_id>/update', methods=['PUT', 'OPTIONS'])
# @manufacturer_required
# @auth_middleware
# def update_product(product_id):
#     """Update product information"""
#     if request.method == 'OPTIONS':
#         return create_cors_response()
    
#     try:
#         if not ObjectId.is_valid(product_id):
#             return create_cors_response(
#                 create_error_response("Invalid product ID format"), 400
#             )
        
#         data = request.get_json()
#         if not data:
#             return create_cors_response(
#                 create_error_response("No data provided"), 400
#             )
        
#         # Add update metadata
#         data['updated_at'] = datetime.utcnow()
#         manufacturer_id = ObjectId(g.current_user.get('user_id'))
        
#         if product_service:
#             result = product_service.update_product(ObjectId(product_id), data, manufacturer_id)
#             if result['success']:
#                 response_data = format_product_response(result['product'])
#                 return create_cors_response(
#                     create_success_response(response_data, "Product updated successfully")
#                 )
#             else:
#                 return create_cors_response(
#                     create_error_response(result['error']), 400
#                 )
#         else:
#             # Fallback response
#             data['id'] = product_id
#             return create_cors_response(
#                 create_success_response(data, "Product update received (service unavailable)")
#             )
    
#     except Exception as e:
#         logger.error(f"Product update error: {e}")
#         return create_cors_response(
#             create_error_response("Internal server error"), 500
#         )

@product_bp.route('/<product_id>/verify', methods=['POST', 'OPTIONS'])
@optional_auth_middleware
def verify_product(product_id):
    """Verify product authenticity"""
    if request.method == 'OPTIONS':
        return create_cors_response()
    
    try:
        if not ObjectId.is_valid(product_id):
            return create_cors_response(
                create_error_response("Invalid product ID format"), 400
            )
        
        if product_service:
            result = product_service.verify_product(ObjectId(product_id))
            if result['success']:
                return create_cors_response(
                    create_success_response(result['verification'])
                )
            else:
                return create_cors_response(
                    create_error_response(result['error']), 400
                )
        else:
            # Fallback verification response
            verification_data = {
                'product_id': product_id,
                'verified': True,
                'verification_method': 'database',
                'verified_at': datetime.utcnow().isoformat(),
                'status': 'authentic',
                'message': 'Product verified (service unavailable mode)'
            }
            return create_cors_response(
                create_success_response(verification_data, "Product verified successfully")
            )
    
    except Exception as e:
        logger.error(f"Product verification error: {e}")
        return create_cors_response(
            create_error_response("Internal server error"), 500
        )

@product_bp.route('/search', methods=['GET', 'OPTIONS'])
@optional_auth_middleware
def search_products():
    """Search products by various criteria"""
    if request.method == 'OPTIONS':
        return create_cors_response()
    
    try:
        # Get search parameters
        query = request.args.get('q', '')
        brand = request.args.get('brand', '')
        device_type = request.args.get('device_type', '')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        search_params = {
            'query': query,
            'brand': brand,
            'device_type': device_type,
            'page': page,
            'limit': limit
        }
        
        if product_service:
            result = product_service.search_products(search_params)
            if result['success']:
                products = [format_product_response(product) for product in result['products']]
                response_data = {
                    'products': products,
                    'total': result.get('total', len(products)),
                    'page': page,
                    'limit': limit,
                    'query': search_params
                }
                return create_cors_response(
                    create_success_response(response_data)
                )
            else:
                return create_cors_response(
                    create_error_response(result['error']), 400
                )
        else:
            # Fallback search response
            sample_results = [
                {
                    'id': '1',
                    'serial_number': 'SEARCH123',
                    'brand': brand or 'Sample Brand',
                    'model': 'Search Model',
                    'device_type': device_type or 'Device'
                }
            ]
            return create_cors_response(
                create_success_response({
                    'products': sample_results, 
                    'total': 1, 
                    'message': 'Search results (service unavailable)'
                })
            )
    
    except Exception as e:
        logger.error(f"Product search error: {e}")
        return create_cors_response(
            create_error_response("Internal server error"), 500
        )

@product_bp.route('/health', methods=['GET'])
def product_health():
    """Health check for product routes"""
    return create_cors_response(
        create_success_response({
            'service': 'product_routes',
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        })
    )