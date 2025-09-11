"""
Webhook handlers for receiving notifications from external systems
Handles blockchain events, manufacturer system notifications, and verification updates
"""

from flask import Blueprint, request, jsonify, make_response
from bson import ObjectId
from datetime import datetime, timezone
import hashlib
import hmac
import json
import traceback
import os
from utils.helper_functions import get_db_connection, get_current_utc

webhook_bp = Blueprint('webhook_handlers', __name__)

def create_cors_response(data, status_code=200):
    """Create CORS-enabled response"""
    response = make_response(jsonify(data), status_code)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-API-Key,X-Webhook-Signature'
    return response

class WebhookValidator:
    """Validates webhook signatures and payloads"""
    
    @staticmethod
    def verify_signature(payload, signature, secret):
        """Verify webhook signature"""
        if not signature or not secret:
            return False
        
        # Remove 'sha256=' prefix if present
        if signature.startswith('sha256='):
            signature = signature[7:]
        
        # Calculate expected signature
        expected = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected, signature)
    
    @staticmethod
    def validate_blockchain_event(data):
        """Validate blockchain event payload"""
        required_fields = ['event_type', 'transaction_hash', 'block_number']
        return all(field in data for field in required_fields)
    
    @staticmethod
    def validate_verification_event(data):
        """Validate verification event payload"""
        required_fields = ['serial_number', 'timestamp', 'result']
        return all(field in data for field in required_fields)

class WebhookProcessor:
    """Processes different types of webhook events"""
    
    @staticmethod
    def process_blockchain_event(data):
        """Process blockchain-related events"""
        db = get_db_connection()
        event_type = data['event_type']
        
        try:
            if event_type == 'product_registered':
                return WebhookProcessor._handle_product_registration(db, data)
            elif event_type == 'ownership_transferred':
                return WebhookProcessor._handle_ownership_transfer(db, data)
            elif event_type == 'verification_completed':
                return WebhookProcessor._handle_verification_update(db, data)
            else:
                print(f"Unknown blockchain event type: {event_type}")
                return {"status": "ignored", "reason": f"Unknown event type: {event_type}"}
                
        except Exception as e:
            print(f"Error processing blockchain event: {e}")
            raise
    
    @staticmethod
    def _handle_product_registration(db, data):
        """Handle product registration blockchain event"""
        serial_number = data.get('serial_number')
        transaction_hash = data['transaction_hash']
        block_number = data['block_number']
        manufacturer_address = data.get('manufacturer_address')
        
        if not serial_number:
            return {"status": "error", "message": "Serial number required"}
        
        # Update product in database
        result = db.products.update_one(
            {"serial_number": serial_number},
            {
                "$set": {
                    "blockchain_verified": True,
                    "registration_type": "blockchain_confirmed",
                    "transaction_hash": transaction_hash,
                    "block_number": block_number,
                    "blockchain_timestamp": data.get('timestamp', get_current_utc()),
                    "updated_at": get_current_utc()
                }
            }
        )
        
        if result.matched_count > 0:
            # Log the blockchain confirmation
            db.blockchain_events.insert_one({
                "event_type": "product_registered",
                "serial_number": serial_number,
                "transaction_hash": transaction_hash,
                "block_number": block_number,
                "manufacturer_address": manufacturer_address,
                "processed_at": get_current_utc()
            })
            
            return {"status": "success", "message": "Product blockchain registration confirmed"}
        else:
            return {"status": "not_found", "message": "Product not found in database"}
    
    @staticmethod
    def _handle_ownership_transfer(db, data):
        """Handle ownership transfer blockchain event"""
        serial_number = data.get('serial_number')
        from_address = data.get('from_address')
        to_address = data.get('to_address')
        transaction_hash = data['transaction_hash']
        
        if not all([serial_number, from_address, to_address]):
            return {"status": "error", "message": "Missing required transfer data"}
        
        # Create ownership transfer record
        transfer_record = {
            "serial_number": serial_number,
            "from_address": from_address,
            "to_address": to_address,
            "transaction_hash": transaction_hash,
            "block_number": data['block_number'],
            "transfer_date": data.get('timestamp', get_current_utc()),
            "created_at": get_current_utc()
        }
        
        # Update product ownership
        db.products.update_one(
            {"serial_number": serial_number},
            {
                "$set": {
                    "current_owner": to_address,
                    "updated_at": get_current_utc()
                },
                "$push": {
                    "ownership_history": {
                        "owner_address": to_address,
                        "previous_owner": from_address,
                        "transfer_date": transfer_record["transfer_date"],
                        "transaction_hash": transaction_hash,
                        "transfer_type": "blockchain"
                    }
                }
            }
        )
        
        # Store transfer record
        db.ownership_transfers.insert_one(transfer_record)
        
        return {"status": "success", "message": "Ownership transfer processed"}
    
    @staticmethod
    def _handle_verification_update(db, data):
        """Handle verification completion event"""
        serial_number = data.get('serial_number')
        verification_result = data.get('result')
        confidence_score = data.get('confidence_score', 0)
        
        # Update verification logs
        db.verifications.insert_one({
            "serial_number": serial_number,
            "authentic": verification_result.get('authentic', False),
            "confidence_score": confidence_score,
            "source": "blockchain_webhook",
            "transaction_hash": data['transaction_hash'],
            "block_number": data['block_number'],
            "timestamp": data.get('timestamp', get_current_utc()),
            "created_at": get_current_utc()
        })
        
        return {"status": "success", "message": "Verification logged"}
    
    @staticmethod
    def process_manufacturer_notification(data):
        """Process notifications from manufacturer systems"""
        db = get_db_connection()
        notification_type = data.get('type')
        
        try:
            if notification_type == 'product_batch_registered':
                return WebhookProcessor._handle_batch_registration(db, data)
            elif notification_type == 'counterfeit_reported':
                return WebhookProcessor._handle_counterfeit_report(db, data)
            elif notification_type == 'recall_initiated':
                return WebhookProcessor._handle_recall_notification(db, data)
            else:
                return {"status": "ignored", "reason": f"Unknown notification type: {notification_type}"}
                
        except Exception as e:
            print(f"Error processing manufacturer notification: {e}")
            raise
    
    @staticmethod
    def _handle_batch_registration(db, data):
        """Handle batch product registration notification"""
        products = data.get('products', [])
        manufacturer_id = data.get('manufacturer_id')
        batch_id = data.get('batch_id')
        
        processed_count = 0
        failed_products = []
        
        for product_data in products:
            try:
                # Create product record
                product_record = {
                    "serial_number": product_data['serial_number'],
                    "brand": product_data.get('brand'),
                    "model": product_data.get('model'),
                    "device_type": product_data.get('device_type'),
                    "manufacturer_id": ObjectId(manufacturer_id),
                    "batch_id": batch_id,
                    "registration_type": "batch_registered",
                    "blockchain_verified": False,
                    "created_at": get_current_utc()
                }
                
                db.products.insert_one(product_record)
                processed_count += 1
                
            except Exception as e:
                failed_products.append({
                    "serial_number": product_data.get('serial_number'),
                    "error": str(e)
                })
        
        return {
            "status": "success",
            "processed": processed_count,
            "failed": len(failed_products),
            "failed_products": failed_products
        }
    
    @staticmethod
    def _handle_counterfeit_report(db, data):
        """Handle counterfeit product report"""
        report_data = {
            "serial_number": data.get('serial_number'),
            "manufacturer_id": ObjectId(data['manufacturer_id']) if data.get('manufacturer_id') else None,
            "report_type": data.get('report_type', 'counterfeit'),
            "description": data.get('description'),
            "reporter_contact": data.get('reporter_contact'),
            "evidence": data.get('evidence', []),
            "severity": data.get('severity', 'medium'),
            "status": "open",
            "created_at": get_current_utc(),
            "webhook_source": True
        }
        
        result = db.counterfeit_reports.insert_one(report_data)
        
        return {
            "status": "success",
            "report_id": str(result.inserted_id),
            "message": "Counterfeit report logged"
        }
    
    @staticmethod
    def _handle_recall_notification(db, data):
        """Handle product recall notification"""
        recall_data = {
            "manufacturer_id": ObjectId(data['manufacturer_id']),
            "recall_id": data.get('recall_id'),
            "affected_products": data.get('affected_products', []),
            "recall_reason": data.get('reason'),
            "severity_level": data.get('severity', 'medium'),
            "recall_date": data.get('recall_date', get_current_utc()),
            "created_at": get_current_utc()
        }
        
        result = db.product_recalls.insert_one(recall_data)
        
        # Update affected products
        if recall_data['affected_products']:
            db.products.update_many(
                {"serial_number": {"$in": recall_data['affected_products']}},
                {
                    "$set": {
                        "recall_status": "recalled",
                        "recall_id": recall_data['recall_id'],
                        "updated_at": get_current_utc()
                    }
                }
            )
        
        return {
            "status": "success",
            "recall_id": str(result.inserted_id),
            "affected_products": len(recall_data['affected_products'])
        }

# Webhook Endpoints

@webhook_bp.route('/blockchain-events', methods=['POST'])
def handle_blockchain_webhook():
    """Handle blockchain event webhooks"""
    try:
        # Get raw payload for signature verification
        raw_payload = request.get_data()
        
        # Verify signature if configured
        signature = request.headers.get('X-Webhook-Signature')
        webhook_secret = os.getenv('BLOCKCHAIN_WEBHOOK_SECRET')
        
        if webhook_secret and not WebhookValidator.verify_signature(raw_payload, signature, webhook_secret):
            return create_cors_response({"error": "Invalid signature"}, 401)
        
        # Parse JSON payload
        try:
            data = json.loads(raw_payload)
        except json.JSONDecodeError:
            return create_cors_response({"error": "Invalid JSON payload"}, 400)
        
        # Validate payload structure
        if not WebhookValidator.validate_blockchain_event(data):
            return create_cors_response({"error": "Invalid blockchain event payload"}, 400)
        
        # Process the event
        result = WebhookProcessor.process_blockchain_event(data)
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Blockchain webhook error: {e}")
        traceback.print_exc()
        return create_cors_response({"error": "Internal server error"}, 500)

@webhook_bp.route('/manufacturer-notifications', methods=['POST'])
def handle_manufacturer_webhook():
    """Handle manufacturer system notifications"""
    try:
        data = request.get_json()
        if not data:
            return create_cors_response({"error": "JSON payload required"}, 400)
        
        # Basic validation
        if 'type' not in data:
            return create_cors_response({"error": "Notification type required"}, 400)
        
        # Process the notification
        result = WebhookProcessor.process_manufacturer_notification(data)
        
        # Log the webhook for audit
        db = get_db_connection()
        db.webhook_logs.insert_one({
            "type": "manufacturer_notification",
            "payload": data,
            "result": result,
            "timestamp": get_current_utc(),
            "source_ip": request.remote_addr
        })
        
        return create_cors_response(result, 200)
        
    except Exception as e:
        print(f"Manufacturer webhook error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@webhook_bp.route('/verification-updates', methods=['POST'])
def handle_verification_webhook():
    """Handle verification result updates"""
    try:
        data = request.get_json()
        if not data:
            return create_cors_response({"error": "JSON payload required"}, 400)
        
        if not WebhookValidator.validate_verification_event(data):
            return create_cors_response({"error": "Invalid verification payload"}, 400)
        
        db = get_db_connection()
        
        # Log verification update
        verification_log = {
            "serial_number": data['serial_number'],
            "authentic": data['result'].get('authentic', False),
            "confidence_score": data['result'].get('confidence_score', 0),
            "source": "webhook",
            "external_id": data.get('external_id'),
            "timestamp": data.get('timestamp', get_current_utc()),
            "created_at": get_current_utc()
        }
        
        db.verifications.insert_one(verification_log)
        
        return create_cors_response({
            "status": "success",
            "message": "Verification logged"
        }, 200)
        
    except Exception as e:
        print(f"Verification webhook error: {e}")
        return create_cors_response({"error": "Internal server error"}, 500)

@webhook_bp.route('/webhook-test', methods=['GET', 'POST'])
def webhook_test():
    """Test endpoint for webhook functionality"""
    if request.method == 'GET':
        return create_cors_response({
            "status": "active",
            "service": "webhook_handlers",
            "endpoints": [
                "/blockchain-events",
                "/manufacturer-notifications", 
                "/verification-updates",
                "/webhook-test"
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, 200)
    
    else:  # POST
        data = request.get_json() or {}
        
        # Log test webhook
        db = get_db_connection()
        db.webhook_logs.insert_one({
            "type": "test",
            "payload": data,
            "timestamp": get_current_utc(),
            "source_ip": request.remote_addr
        })
        
        return create_cors_response({
            "status": "success",
            "message": "Test webhook received",
            "received_data": data
        }, 200)

# Error handlers for webhook blueprint
@webhook_bp.errorhandler(400)
def bad_request(error):
    return create_cors_response({"error": "Bad request"}, 400)

@webhook_bp.errorhandler(401)
def unauthorized(error):
    return create_cors_response({"error": "Unauthorized"}, 401)

@webhook_bp.errorhandler(500)
def internal_error(error):
    return create_cors_response({"error": "Internal server error"}, 500)