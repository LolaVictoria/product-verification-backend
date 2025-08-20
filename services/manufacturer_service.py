
from datetime import datetime
from venv import logger
from models.manufacturer import Manufacturer
from models.audit_log import AuditLog
from services.blockchain_service import BlockchainService
from utils.helpers import validate_object_ids, convert_objectids_to_strings

class ManufacturerService:
    """Service for manufacturer business logic"""
    
    @staticmethod
    def get_pending_manufacturers():
        """Get all pending manufacturers"""
        manufacturers = Manufacturer.find_pending()
        return convert_objectids_to_strings(manufacturers)
    
    @staticmethod
    def get_authorized_manufacturers():
        """Get all authorized manufacturers"""
        manufacturers = Manufacturer.find_authorized()
        return convert_objectids_to_strings(manufacturers)
    
    @staticmethod
    def batch_authorize_manufacturers(manufacturer_ids, admin_email):
        """Batch authorize manufacturers with blockchain integration"""
        try:
            # Validate and convert IDs
            object_ids = validate_object_ids(manufacturer_ids)
            
            # Update database
            update_result = Manufacturer.batch_authorize(object_ids, admin_email)
            
            if update_result.modified_count == 0:
                raise ValueError("No manufacturers were updated")
            
            # Get updated manufacturers for blockchain
            authorized_manufacturers = Manufacturer.find_by_ids(object_ids)
            wallet_addresses = [m['wallet_address'] for m in authorized_manufacturers]
            
            # Blockchain interaction
            blockchain_result = BlockchainService.authorize_manufacturers(wallet_addresses)
            
            # Log success
            AuditLog.create({
                'action': 'BATCH_AUTHORIZE',
                'admin_email': admin_email,
                'manufacturers_count': update_result.modified_count,
                'tx_hash': blockchain_result['tx_hash'],
                'gas_used': blockchain_result['gas_used'],
                'status': 'success',
                'details': {
                    'manufacturer_ids': manufacturer_ids,
                    'blockchain_tx': blockchain_result['tx_hash']
                }
            })
            
            return {
                'success': True,
                'authorized_count': update_result.modified_count,
                'tx_hash': blockchain_result['tx_hash'],
                'gas_used': blockchain_result['gas_used']
            }
            
        except Exception as e:
            # Log failure
            AuditLog.create({
                'action': 'BATCH_AUTHORIZE_FAILED',
                'admin_email': admin_email,
                'manufacturers_count': len(manufacturer_ids),
                'status': 'failed',
                'details': {
                    'error': str(e),
                    'manufacturer_ids': manufacturer_ids
                }
            })
            raise e
        

 
    @staticmethod
    def revoke_manufacturer_authorization(manufacturer_id, admin_email):
        """Revoke authorization for a single manufacturer"""
        try:
            # Validate and convert ID
            object_id = validate_object_ids([manufacturer_id])[0]
            
            # Get manufacturer details
            manufacturer = Manufacturer.find_by_ids([object_id])
            if not manufacturer or manufacturer[0].get('status') != 'verified':
                raise ValueError("Manufacturer not found or not currently authorized")
            
            manufacturer_data = manufacturer[0]
            wallet_address = manufacturer_data['wallet_address']
            
            # Blockchain interaction
            blockchain_service = BlockchainService.get_instance()
            blockchain_result = blockchain_service.revoke_manufacturer_authorization(wallet_address)
            
            if not blockchain_result['success']:
                raise Exception(f"Blockchain revocation failed: {blockchain_result.get('error', 'Unknown error')}")
            
            # Update database
            from utils.database import get_db
            db = get_db()
            update_result = db.manufacturers.update_one(
                {'_id': object_id},
                {
                    '$set': {
                        'status': 'suspended',
                        'date_revoked': datetime.utcnow(),
                        'revoked_by': admin_email
                    }
                }
            )
            
            # Log success
            AuditLog.create({
                'action': 'MANUFACTURER_REVOKED',
                'admin_email': admin_email,
                'manufacturers_count': 1,
                'tx_hash': blockchain_result['tx_hash'],
                'gas_used': blockchain_result['gas_used'],
                'status': 'success',
                'details': {
                    'manufacturer_id': manufacturer_id,
                    'wallet_address': wallet_address,
                    'blockchain_tx': blockchain_result['tx_hash']
                }
            })
            
            return {
                'success': True,
                'tx_hash': blockchain_result['tx_hash'],
                'gas_used': blockchain_result['gas_used'],
                'revoked_address': wallet_address
            }
            
        except Exception as e:
            # Log failure
            AuditLog.create({
                'action': 'MANUFACTURER_REVOKE_FAILED',
                'admin_email': admin_email,
                'status': 'failed',
                'details': {
                    'error': str(e),
                    'manufacturer_id': manufacturer_id
                }
            })
            raise e
    
    @staticmethod
    def verify_manufacturer_blockchain_status(manufacturer_id):
        """Verify manufacturer's blockchain authorization status"""
        try:
            # Get manufacturer from database
            object_id = validate_object_ids([manufacturer_id])[0]
            manufacturer = Manufacturer.find_by_ids([object_id])
            
            if not manufacturer:
                return {'success': False, 'error': 'Manufacturer not found'}
            
            wallet_address = manufacturer[0]['wallet_address']
            
            # Check blockchain status
            blockchain_service = BlockchainService.get_instance()
            blockchain_result = blockchain_service.verify_manufacturer_authorization(wallet_address)
            
            return {
                'success': True,
                'manufacturer_id': manufacturer_id,
                'wallet_address': wallet_address,
                'db_status': manufacturer[0]['status'],
                'blockchain_authorized': blockchain_result.get('authorized', False),
                'status_match': (
                    manufacturer[0]['status'] == 'verified' and 
                    blockchain_result.get('authorized', False)
                ) or (
                    manufacturer[0]['status'] != 'verified' and 
                    not blockchain_result.get('authorized', False)
                )
            }
            
        except Exception as e:
            logger.error(f"Blockchain status verification failed: {e}")
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def get_authorization_cost_estimate(manufacturer_count):
        """Get cost estimate for authorizing manufacturers"""
        try:
            blockchain_service = BlockchainService.get_instance()
            cost_estimate = blockchain_service.estimate_batch_authorization_cost(manufacturer_count)
            
            return {
                'success': True,
                'cost_estimate': cost_estimate,
                'manufacturer_count': manufacturer_count
            }
            
        except Exception as e:
            logger.error(f"Cost estimation failed: {e}")
            return {'success': False, 'error': str(e)}