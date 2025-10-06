"""
External Webhook Routes
Handle webhooks from Stripe, blockchain, and manufacturer integrations
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import logging
import os

from app.services.billing.stripe_service import stripe_service
from app.services.webhook_service import webhook_service
from app.api.middleware.webhook_middleware import webhook_middleware

logger = logging.getLogger(__name__)

webhook_bp = Blueprint('webhooks', __name__, url_prefix='/external/webhooks')


# ===============================
# STRIPE WEBHOOKS
# ===============================

@webhook_bp.route('/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    try:
        payload = request.get_data()
        signature = request.headers.get('Stripe-Signature')
        
        if not payload or not signature:
            logger.warning("Missing payload or signature in Stripe webhook")
            return jsonify({
                'success': False,
                'error': 'Missing payload or signature'
            }), 400
        
        result = stripe_service.handle_webhook(payload, signature)
        
        if result.get('success'):
            logger.info(f"Stripe webhook processed: {result.get('event_type')}")
            return jsonify({
                'success': True,
                'message': 'Webhook processed successfully'
            }), 200
        else:
            logger.error(f"Stripe webhook failed: {result.get('error')}")
            return jsonify({
                'success': False,
                'error': result.get('error', 'Webhook processing failed')
            }), 400
    
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook processing failed'
        }), 500


# ===============================
# BLOCKCHAIN WEBHOOKS
# ===============================

@webhook_bp.route('/blockchain', methods=['POST'])
@webhook_middleware.verify_webhook_signature('BLOCKCHAIN_WEBHOOK_SECRET')
def blockchain_webhook():
    """Handle blockchain event webhooks"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'JSON payload required'
            }), 400
        
        if not webhook_middleware.validate_blockchain_event(data):
            return jsonify({
                'success': False,
                'error': 'Invalid blockchain event payload'
            }), 400
        
        result = webhook_service.process_blockchain_event(data)
        
        return jsonify({
            'success': True,
            'message': 'Blockchain event processed'
        }), 200
        
    except Exception as e:
        logger.error(f"Blockchain webhook error: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook processing failed'
        }), 500


# ===============================
# MANUFACTURER WEBHOOKS
# ===============================

@webhook_bp.route('/manufacturer', methods=['POST'])
def manufacturer_webhook():
    """Handle manufacturer system notifications"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'JSON payload required'
            }), 400
        
        if 'type' not in data:
            return jsonify({
                'success': False,
                'error': 'Notification type required'
            }), 400
        
        result = webhook_service.process_manufacturer_notification(data)
        
        # Log webhook
        from app.config.database import get_db_connection
        db = get_db_connection()
        db.webhook_logs.insert_one({
            'type': 'manufacturer_notification',
            'payload': data,
            'result': result,
            'timestamp': datetime.now(timezone.utc),
            'source_ip': request.remote_addr
        })
        
        return jsonify({
            'success': True,
            'message': 'Notification processed'
        }), 200
        
    except Exception as e:
        logger.error(f"Manufacturer webhook error: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook processing failed'
        }), 500


# ===============================
# VERIFICATION WEBHOOKS
# ===============================

@webhook_bp.route('/verification', methods=['POST'])
def verification_webhook():
    """Handle verification result updates"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'JSON payload required'
            }), 400
        
        if not webhook_middleware.validate_verification_event(data):
            return jsonify({
                'success': False,
                'error': 'Invalid verification payload'
            }), 400
        
        from app.config.database import get_db_connection
        db = get_db_connection()
        
        verification_log = {
            'serial_number': data['serial_number'],
            'authentic': data['result'].get('authentic', False),
            'confidence_score': data['result'].get('confidence_score', 0),
            'source': 'webhook',
            'external_id': data.get('external_id'),
            'timestamp': data.get('timestamp', datetime.now(timezone.utc)),
            'created_at': datetime.now(timezone.utc)
        }
        
        db.verifications.insert_one(verification_log)
        
        return jsonify({
            'success': True,
            'message': 'Verification logged'
        }), 200
        
    except Exception as e:
        logger.error(f"Verification webhook error: {e}")
        return jsonify({
            'success': False,
            'error': 'Webhook processing failed'
        }), 500


# ===============================
# TESTING
# ===============================

@webhook_bp.route('/test', methods=['GET', 'POST'])
def webhook_test():
    """Test webhook functionality"""
    if request.method == 'GET':
        return jsonify({
            'status': 'active',
            'service': 'webhook_handlers',
            'endpoints': [
                '/external/webhooks/stripe',
                '/external/webhooks/blockchain',
                '/external/webhooks/manufacturer',
                '/external/webhooks/verification',
                '/external/webhooks/test'
            ],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    
    else:  # POST
        data = request.get_json() or {}
        
        from app.config.database import get_db_connection
        db = get_db_connection()
        db.webhook_logs.insert_one({
            'type': 'test',
            'payload': data,
            'timestamp': datetime.now(timezone.utc),
            'source_ip': request.remote_addr
        })
        
        return jsonify({
            'success': True,
            'message': 'Test webhook received',
            'received_data': data
        }), 200


# ===============================
# ERROR HANDLERS
# ===============================

@webhook_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'success': False, 'error': 'Bad request'}), 400


@webhook_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'success': False, 'error': 'Unauthorized'}), 401


@webhook_bp.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404


@webhook_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Webhook internal error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500