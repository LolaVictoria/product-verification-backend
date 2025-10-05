from bson import ObjectId
from app.config.database import get_db_connection
from app.utils.date_helpers import date_helper_utils
from app.config.database import get_db_connection

class WebhookService:
    """Processes different types of webhook events"""
    
    @staticmethod
    def process_blockchain_event(data):
        """Process blockchain-related events"""
        db = get_db_connection()
        event_type = data['event_type']
        
        try:
            if event_type == 'product_registered':
                return WebhookService._handle_product_registration(db, data)
            elif event_type == 'ownership_transferred':
                return WebhookService._handle_ownership_transfer(db, data)
            elif event_type == 'verification_completed':
                return WebhookService._handle_verification_update(db, data)
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
                    "blockchain_timestamp": data.get('timestamp', date_helper_utils.get_current_utc()),
                    "updated_at": date_helper_utils.get_current_utc()
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
                "processed_at": date_helper_utils.get_current_utc()
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
            "transfer_date": data.get('timestamp', date_helper_utils.get_current_utc()),
            "created_at": date_helper_utils.get_current_utc()
        }
        
        # Update product ownership
        db.products.update_one(
            {"serial_number": serial_number},
            {
                "$set": {
                    "current_owner": to_address,
                    "updated_at": date_helper_utils.get_current_utc()
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
            "timestamp": data.get('timestamp', date_helper_utils.get_current_utc()),
            "created_at": date_helper_utils.get_current_utc()
        })
        
        return {"status": "success", "message": "Verification logged"}
    
    @staticmethod
    def process_manufacturer_notification(data):
        """Process notifications from manufacturer systems"""
        db = get_db_connection()
        notification_type = data.get('type')
        
        try:
            if notification_type == 'product_batch_registered':
                return WebhookService._handle_batch_registration(db, data)
            elif notification_type == 'counterfeit_reported':
                return WebhookService._handle_counterfeit_report(db, data)
            elif notification_type == 'recall_initiated':
                return WebhookService._handle_recall_notification(db, data)
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
                    "created_at": date_helper_utils.get_current_utc()
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
            "created_at": date_helper_utils.get_current_utc(),
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
            "recall_date": data.get('recall_date', date_helper_utils.get_current_utc()),
            "created_at": date_helper_utils.get_current_utc()
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
                        "updated_at": date_helper_utils.get_current_utc()
                    }
                }
            )
        
        return {
            "status": "success",
            "recall_id": str(result.inserted_id),
            "affected_products": len(recall_data['affected_products'])
        }

webhook_service = WebhookService()