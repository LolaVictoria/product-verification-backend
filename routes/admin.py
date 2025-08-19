from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from services import AuthService, BlockchainService
from utils.helpers import create_error_response, create_success_response
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
admin_bp = Blueprint('admin', __name__)

# Middleware to check admin role
def admin_required(f):
    """Decorator to ensure only admin users can access certain endpoints"""
    def decorated_function(*args, **kwargs):
        try:
            claims = get_jwt()
            user_role = claims.get('role', '').lower()
            
            if user_role != 'admin':
                response, status_code = create_error_response('Admin access required', 403)
                return jsonify(response), status_code
                
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Admin role check error: {str(e)}")
            response, status_code = create_error_response('Authorization error', 401)
            return jsonify(response), status_code
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_bp.route('/dashboard/stats', methods=['GET'])
@jwt_required()
@admin_required
def get_dashboard_stats():
    """Get dashboard statistics for admin overview"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Dashboard stats request from admin: {user_id}")
        
        # Get statistics from AuthService
        stats = AuthService.get_admin_dashboard_stats()
        
        return jsonify({
            'success': True,
            'data': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get dashboard stats', 500)
        return jsonify(response), status_code

@admin_bp.route('/manufacturers/pending', methods=['GET'])
@jwt_required()
@admin_required
def get_pending_manufacturers():
    """Get all manufacturers pending blockchain verification"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Pending manufacturers request from admin: {user_id}")
        
        # Get query parameters for pagination and filtering
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '')
        
        # Get pending manufacturers from database
        result = AuthService.get_pending_manufacturers_paginated(page, per_page, search)
        
        return jsonify({
            'success': True,
            'data': result['manufacturers'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': result['total'],
                'pages': result['pages']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get pending manufacturers error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get pending manufacturers', 500)
        return jsonify(response), status_code

@admin_bp.route('/manufacturers/authorized', methods=['GET'])
@jwt_required()
@admin_required
def get_authorized_manufacturers():
    """Get all authorized manufacturers"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Authorized manufacturers request from admin: {user_id}")
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '')
        
        # Get authorized manufacturers from database
        result = AuthService.get_authorized_manufacturers_paginated(page, per_page, search)
        
        return jsonify({
            'success': True,
            'data': result['manufacturers'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': result['total'],
                'pages': result['pages']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get authorized manufacturers error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get authorized manufacturers', 500)
        return jsonify(response), status_code

@admin_bp.route('/manufacturers/batch-authorize', methods=['POST'])
@jwt_required()
@admin_required
def batch_authorize_manufacturers():
    """Authorize multiple manufacturers in a single blockchain transaction"""
    try:
        user_id = get_jwt_identity()
        admin_claims = get_jwt()
        admin_email = admin_claims.get('email', 'unknown')
        
        data = request.get_json()
        if not data:
            response, status_code = create_error_response('No data provided', 400)
            return jsonify(response), status_code
        
        manufacturer_ids = data.get('manufacturer_ids', [])
        if not manufacturer_ids:
            response, status_code = create_error_response('No manufacturer IDs provided', 400)
            return jsonify(response), status_code
        
        logger.info(f"Batch authorization request from admin {admin_email} for {len(manufacturer_ids)} manufacturers")
        
        # Get manufacturer details from database
        manufacturers = AuthService.get_manufacturers_by_ids(manufacturer_ids)
        if not manufacturers:
            response, status_code = create_error_response('No valid manufacturers found', 404)
            return jsonify(response), status_code
        
        # Extract wallet addresses
        wallet_addresses = [m['wallet_address'] for m in manufacturers]
        
        # Perform blockchain authorization
        from app import blockchain_service
        
        if not blockchain_service or not blockchain_service.is_connected():
            response, status_code = create_error_response('Blockchain service unavailable', 503)
            return jsonify(response), status_code
        
        # Execute batch authorization
        auth_result = blockchain_service.batch_authorize_manufacturers(wallet_addresses)
        
        if not auth_result.get('success'):
            logger.error(f"Batch authorization failed: {auth_result.get('error')}")
            response, status_code = create_error_response(
                f"Blockchain authorization failed: {auth_result.get('error')}", 400
            )
            return jsonify(response), status_code
        
        # Update database status for authorized manufacturers
        update_result = AuthService.update_manufacturers_blockchain_status(
            manufacturer_ids, 'verified', admin_email, auth_result.get('tx_hash')
        )
        
        if not update_result['success']:
            logger.error(f"Database update failed after successful blockchain authorization")
            # Note: Blockchain transaction succeeded, but database update failed
            response, status_code = create_error_response(
                'Blockchain authorization succeeded but database update failed. Please contact support.', 500
            )
            return jsonify(response), status_code
        
        # Log the action for audit trail
        AuthService.log_admin_action(
            admin_id=user_id,
            admin_email=admin_email,
            action='BATCH_AUTHORIZE',
            details={
                'manufacturer_count': len(manufacturer_ids),
                'manufacturer_ids': manufacturer_ids,
                'wallet_addresses': wallet_addresses,
                'tx_hash': auth_result.get('tx_hash'),
                'gas_used': auth_result.get('gas_used')
            }
        )
        
        logger.info(f"Successfully authorized {len(manufacturer_ids)} manufacturers. TX: {auth_result.get('tx_hash')}")
        
        return jsonify({
            'success': True,
            'message': f'Successfully authorized {len(manufacturer_ids)} manufacturers',
            'data': {
                'authorized_count': len(manufacturer_ids),
                'tx_hash': auth_result.get('tx_hash'),
                'gas_used': auth_result.get('gas_used'),
                'gas_saved_estimate': auth_result.get('gas_saved_vs_individual', 'N/A')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Batch authorization error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Batch authorization failed', 500)
        return jsonify(response), status_code

@admin_bp.route('/manufacturers/<int:manufacturer_id>/revoke', methods=['POST'])
@jwt_required()
@admin_required
def revoke_manufacturer_authorization(manufacturer_id):
    """Revoke authorization for a specific manufacturer"""
    try:
        user_id = get_jwt_identity()
        admin_claims = get_jwt()
        admin_email = admin_claims.get('email', 'unknown')
        
        logger.info(f"Authorization revocation request from admin {admin_email} for manufacturer {manufacturer_id}")
        
        # Get manufacturer details
        manufacturer = AuthService.get_manufacturer_by_id(manufacturer_id)
        if not manufacturer:
            response, status_code = create_error_response('Manufacturer not found', 404)
            return jsonify(response), status_code
        
        if manufacturer['blockchain_status'] != 'verified':
            response, status_code = create_error_response('Manufacturer is not currently authorized', 400)
            return jsonify(response), status_code
        
        # Perform blockchain revocation
        from app import blockchain_service
        
        if not blockchain_service or not blockchain_service.is_connected():
            response, status_code = create_error_response('Blockchain service unavailable', 503)
            return jsonify(response), status_code
        
        # Execute revocation on blockchain
        revoke_result = blockchain_service.revoke_manufacturer_authorization(manufacturer['wallet_address'])
        
        if not revoke_result.get('success'):
            logger.error(f"Blockchain revocation failed: {revoke_result.get('error')}")
            response, status_code = create_error_response(
                f"Blockchain revocation failed: {revoke_result.get('error')}", 400
            )
            return jsonify(response), status_code
        
        # Update database status
        update_result = AuthService.update_manufacturer_blockchain_status(
            manufacturer_id, 'revoked', admin_email, revoke_result.get('tx_hash')
        )
        
        if not update_result['success']:
            logger.error(f"Database update failed after successful blockchain revocation")
            response, status_code = create_error_response(
                'Blockchain revocation succeeded but database update failed. Please contact support.', 500
            )
            return jsonify(response), status_code
        
        # Log the action
        AuthService.log_admin_action(
            admin_id=user_id,
            admin_email=admin_email,
            action='REVOKE_AUTHORIZATION',
            details={
                'manufacturer_id': manufacturer_id,
                'wallet_address': manufacturer['wallet_address'],
                'business_name': manufacturer['business_name'],
                'tx_hash': revoke_result.get('tx_hash')
            }
        )
        
        logger.info(f"Successfully revoked authorization for manufacturer {manufacturer_id}")
        
        return jsonify({
            'success': True,
            'message': 'Manufacturer authorization revoked successfully',
            'data': {
                'tx_hash': revoke_result.get('tx_hash')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Authorization revocation error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Authorization revocation failed', 500)
        return jsonify(response), status_code

@admin_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@admin_required
def get_audit_logs():
    """Get admin audit logs"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Audit logs request from admin: {user_id}")
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        action_filter = request.args.get('action', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Get audit logs from database
        result = AuthService.get_admin_audit_logs_paginated(
            page, per_page, action_filter, date_from, date_to
        )
        
        return jsonify({
            'success': True,
            'data': result['logs'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': result['total'],
                'pages': result['pages']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get audit logs error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get audit logs', 500)
        return jsonify(response), status_code

@admin_bp.route('/manufacturers/<int:manufacturer_id>/details', methods=['GET'])
@jwt_required()
@admin_required
def get_manufacturer_details(manufacturer_id):
    """Get detailed information about a specific manufacturer"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Manufacturer details request from admin {user_id} for manufacturer {manufacturer_id}")
        
        # Get manufacturer details
        manufacturer = AuthService.get_manufacturer_details(manufacturer_id)
        if not manufacturer:
            response, status_code = create_error_response('Manufacturer not found', 404)
            return jsonify(response), status_code
        
        # Get blockchain verification status
        from app import blockchain_service
        blockchain_status = {'verified': False, 'error': 'Blockchain service unavailable'}
        
        if blockchain_service and blockchain_service.is_connected():
            try:
                verification_result = blockchain_service.verify_manufacturer_authorization(
                    manufacturer['wallet_address']
                )
                blockchain_status = verification_result
            except Exception as e:
                logger.error(f"Blockchain verification error: {e}")
                blockchain_status = {'verified': False, 'error': str(e)}
        
        return jsonify({
            'success': True,
            'data': {
                'manufacturer': manufacturer,
                'blockchain_status': blockchain_status
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get manufacturer details error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get manufacturer details', 500)
        return jsonify(response), status_code

@admin_bp.route('/system/blockchain-status', methods=['GET'])
@jwt_required()
@admin_required
def get_blockchain_status():
    """Get blockchain service status and gas price information"""
    try:
        user_id = get_jwt_identity()
        logger.info(f"Blockchain status request from admin: {user_id}")
        
        from app import blockchain_service
        
        if not blockchain_service:
            return jsonify({
                'success': True,
                'data': {
                    'connected': False,
                    'error': 'Blockchain service not initialized'
                }
            }), 200
        
        # Check connection status
        is_connected = blockchain_service.is_connected()
        
        status_data = {
            'connected': is_connected,
            'provider_url': getattr(blockchain_service, 'provider_url', 'Unknown'),
            'contract_address': getattr(blockchain_service, 'contract_address', 'Unknown')
        }
        
        if is_connected:
            try:
                # Get gas price information
                gas_info = blockchain_service.get_gas_price_estimate()
                status_data.update(gas_info)
                
                # Get latest block info
                latest_block = blockchain_service.get_latest_block()
                if latest_block:
                    status_data['latest_block'] = {
                        'number': latest_block.number,
                        'timestamp': latest_block.timestamp,
                        'gas_used': latest_block.gasUsed,
                        'gas_limit': latest_block.gasLimit
                    }
            except Exception as e:
                logger.error(f"Error getting blockchain info: {e}")
                status_data['info_error'] = str(e)
        
        return jsonify({
            'success': True,
            'data': status_data
        }), 200
        
    except Exception as e:
        logger.error(f"Blockchain status error: {str(e)}", exc_info=True)
        response, status_code = create_error_response('Failed to get blockchain status', 500)
        return jsonify(response), status_code

# Error handlers for the admin blueprint
@admin_bp.errorhandler(403)
def forbidden(error):
    response, status_code = create_error_response('Admin access required', 403)
    return jsonify(response), status_code

@admin_bp.errorhandler(404)
def not_found(error):
    response, status_code = create_error_response('Resource not found', 404)
    return jsonify(response), status_code

@admin_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Admin internal server error: {str(error)}")
    response, status_code = create_error_response('Internal server error', 500)
    return jsonify(response), status_code