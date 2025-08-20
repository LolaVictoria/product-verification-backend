from datetime import datetime
from utils.database import get_db

class Manufacturer:
    """Manufacturer model for database operations"""
    
    @staticmethod
    def find_pending():
        """Get all pending manufacturers"""
        db = get_db()
        return list(db.users.find(
            {'verification_status': 'pending_'}
        ).sort('date_registered', -1))
    
    @staticmethod
    def find_authorized():
        """Get all authorized manufacturers"""
        db = get_db()
        return list(db.users.find(
            {'verification_status': 'verified'}
        ).sort('date_authorized', -1))
    
    @staticmethod
    def batch_authorize(manufacturer_ids, admin_email):
        """Batch authorize manufacturers"""
        db = get_db()
        
        update_result = db.users.update_many(
            {
                '_id': {'$in': manufacturer_ids},
                'verification_status': 'pending'
            },
            {
                '$set': {
                    'verification_status': 'verified',
                    'date_authorized': datetime.utcnow(),
                    'authorized_by': admin_email
                }
            }
        )
        
        return update_result
    
    @staticmethod
    def find_by_ids(manufacturer_ids):
        """Find manufacturers by IDs"""
        db = get_db()
        return list(db.users.find({
            '_id': {'$in': manufacturer_ids}
        }))
    
    @staticmethod
    def create(manufacturer_data):
        """Create a new manufacturer"""
        db = get_db()
        manufacturer_data['date_registered'] = datetime.utcnow()
        manufacturer_data['status'] = 'pending_verification'
        return db.manufacturers.insert_one(manufacturer_data)