import logging
from typing import Dict, Any
from bson import ObjectId
import pymongo
from app.utils.date_helpers import date_helper_utils
from app.services.webhook_service import webhook_service
from app.validators.product_validator import product_validator
logger = logging.getLogger(__name__)

class OwnershipService:
    """Handles product ownership transfers"""
    def __init__(self, db):
        self.db = db
        self.webhook_processor = webhook_service

    def transfer_ownership_via_api(self, transfer_data: Dict[str, Any], manufacturer_id: str) -> Dict[str, Any]:
        """Transfer product ownership via API"""
        try:
            validation_error = product_validator.validate_ownership_transfer(transfer_data)
            if validation_error:
                return {'success': False, 'error': validation_error}

            product = self.db.products.find_one({
                'serial_number': transfer_data['serial_number'],
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            if not product:
                return {'success': False, 'error': 'Product not found or access denied'}

            transfer_doc = {
                'serial_number': transfer_data['serial_number'],
                'product_id': str(product['_id']),
                'from_manufacturer_id': ObjectId(manufacturer_id),
                'new_owner_address': transfer_data['new_owner_address'],
                'transfer_reason': transfer_data['transfer_reason'],
                'sale_price': transfer_data.get('sale_price', 0),
                'transfer_date': date_helper_utils.get_current_utc(),
                'status': 'completed'
            }

            result = self.db.ownership_transfers.insert_one(transfer_doc)

            self.db.products.update_one(
                {'_id': product['_id']},
                {
                    '$set': {
                        'current_owner': transfer_data['new_owner_address'],
                        'updated_at': date_helper_utils.get_current_utc()
                    },
                    '$push': {
                        'ownership_history': {
                            'from_manufacturer_id': ObjectId(manufacturer_id),
                            'to_owner_address': transfer_data['new_owner_address'],
                            'transfer_date': date_helper_utils.get_current_utc(),
                            'reason': transfer_data['transfer_reason']
                        }
                    }
                }
            )

            # Notify via webhook
            self.webhook_processor.process_blockchain_event({
                'event_type': 'ownership_transferred',
                'serial_number': transfer_data['serial_number'],
                'from_address': product.get('current_owner', ''),
                'to_address': transfer_data['new_owner_address'],
                'transaction_hash': transfer_data.get('transaction_hash', ''),
                'block_number': transfer_data.get('block_number', 0),
                'timestamp': date_helper_utils.get_current_utc().isoformat()
            })

            return {
                'success': True,
                'transfer_id': str(result.inserted_id)
            }

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error transferring ownership: {str(e)}")
            return {'success': False, 'error': 'Failed to transfer ownership'}
        except Exception as e:
            logger.error(f"Error transferring ownership: {str(e)}")
            return {'success': False, 'error': 'Failed to transfer ownership'}

