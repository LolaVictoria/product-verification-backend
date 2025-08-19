import logging
from datetime import datetime, timedelta
from math import ceil
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash
import json

logger = logging.getLogger(__name__)

class AdminService:
    
    # Initialize MongoDB connection (adjust connection string as needed)
    def __init__(self, mongodb_uri="mongodb://localhost:27017/", db_name="your_app_db"):
        self.client = MongoClient(mongodb_uri)
        self.db = self.client[db_name]
        self.users = self.db.users
        self.audit_logs = self.db.admin_audit_logs
    
    @classmethod
    def get_db_instance(cls):
        """Get a singleton instance of the database connection"""
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance
    
    @staticmethod
    def get_manufacturer_by_id(manufacturer_id):
        """Get manufacturer details by ID"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Convert to ObjectId if it's a string
            if isinstance(manufacturer_id, str):
                manufacturer_id = ObjectId(manufacturer_id)
            
            manufacturer = db_instance.users.find_one({
                '_id': manufacturer_id,
                'role': 'manufacturer'
            })
            
            if manufacturer:
                # Convert ObjectId to string for JSON serialization
                manufacturer['id'] = str(manufacturer['_id'])
                del manufacturer['_id']
                return manufacturer
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting manufacturer by ID {manufacturer_id}: {e}")
            return None
    
    @staticmethod
    def get_manufacturer_details(manufacturer_id):
        """Get detailed manufacturer information including activity history"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Get basic manufacturer info
            manufacturer = AuthService.get_manufacturer_by_id(manufacturer_id)
            if not manufacturer:
                return None
            
            # Convert back to ObjectId for queries
            obj_id = ObjectId(manufacturer['id'])
            
            # Count products registered by this manufacturer
            products_registered = db_instance.db.products.count_documents({
                'manufacturer_id': obj_id
            })
            
            # Get activity history (you can customize this based on your needs)
            activity_history = [
                {
                    'action': 'Account Created',
                    'timestamp': manufacturer['created_at'],
                    'details': 'Manufacturer account created'
                }
            ]
            
            # Add authorization event if verified
            if manufacturer.get('blockchain_status') == 'verified' and manufacturer.get('authorized_at'):
                activity_history.append({
                    'action': 'Account Authorized',
                    'timestamp': manufacturer['authorized_at'],
                    'details': f'Authorized by {manufacturer.get("authorized_by", "admin")}'
                })
            
            additional_details = {
                'products_registered': products_registered,
                'last_login': manufacturer.get('last_login'),
                'registration_ip': manufacturer.get('registration_ip'),
                'verification_attempts': manufacturer.get('verification_attempts', 1),
                'activity_history': activity_history
            }
            
            # Merge basic info with additional details
            detailed_info = {**manufacturer, **additional_details}
            
            return detailed_info
            
        except Exception as e:
            logger.error(f"Error getting manufacturer details for ID {manufacturer_id}: {e}")
            return None
    
    @staticmethod
    def create_admin_user(username, email, password):
        """Create an admin user account (for initial setup)"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Check if admin user already exists
            existing_admin = db_instance.users.find_one({
                '$or': [
                    {'email': email},
                    {'username': username}
                ]
            })
            
            if existing_admin:
                return {
                    'success': False,
                    'error': 'Admin user with this email or username already exists'
                }
            
            hashed_password = generate_password_hash(password)
            admin_user = {
                'username': username,
                'email': email,
                'password_hash': hashed_password,
                'role': 'admin',
                'is_active': True,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            result = db_instance.users.insert_one(admin_user)
            
            logger.info(f"Admin user created: {email}")
            
            return {
                'success': True,
                'message': 'Admin user created successfully',
                'user_id': str(result.inserted_id)
            }
            
        except Exception as e:
            logger.error(f"Error creating admin user: {e}")
            return {
                'success': False,
                'error': str(e)
            }
        
    @staticmethod
    def get_admin_dashboard_stats():
        """Get dashboard statistics for admin overview"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Count pending manufacturers
            pending_count = db_instance.users.count_documents({
                'role': 'manufacturer',
                'blockchain_status': 'pending_verification'
            })
            
            # Count authorized manufacturers
            authorized_count = db_instance.users.count_documents({
                'role': 'manufacturer',
                'blockchain_status': 'verified'
            })
            
            # Total manufacturers
            total_manufacturers = db_instance.users.count_documents({'role': 'manufacturer'})
            
            # Total developers
            total_developers = db_instance.users.count_documents({'role': 'developer'})
            
            # Recent registrations (last 7 days)
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            recent_registrations = db_instance.users.count_documents({
                'role': 'manufacturer',
                'created_at': {'$gte': seven_days_ago.isoformat()}
            })
            
            # Total audit logs
            audit_logs_count = db_instance.audit_logs.count_documents({})
            
            return {
                'pending_manufacturers': pending_count,
                'authorized_manufacturers': authorized_count,
                'total_manufacturers': total_manufacturers,
                'total_developers': total_developers,
                'recent_registrations_7d': recent_registrations,
                'total_audit_logs': audit_logs_count,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {
                'pending_manufacturers': 0,
                'authorized_manufacturers': 0,
                'total_manufacturers': 0,
                'total_developers': 0,
                'recent_registrations_7d': 0,
                'total_audit_logs': 0,
                'error': str(e)
            }
    
    @staticmethod
    def get_pending_manufacturers_paginated(page=1, per_page=50, search=''):
        """Get paginated list of manufacturers pending blockchain verification"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Base query
            query = {
                'role': 'manufacturer',
                'blockchain_status': 'pending_verification'
            }
            
            # Add search filter if provided
            if search:
                search_regex = {'$regex': search, '$options': 'i'}
                query['$or'] = [
                    {'username': search_regex},
                    {'email': search_regex},
                    {'business_name': search_regex},
                    {'wallet_address': search_regex}
                ]
            
            # Get total count
            total = db_instance.users.count_documents(query)
            pages = ceil(total / per_page)
            
            # Get paginated results
            skip = (page - 1) * per_page
            manufacturers_cursor = db_instance.users.find(query).skip(skip).limit(per_page)
            
            manufacturers = []
            for manufacturer in manufacturers_cursor:
                manufacturer['id'] = str(manufacturer['_id'])
                del manufacturer['_id']
                # Remove sensitive fields
                manufacturer.pop('password_hash', None)
                manufacturers.append(manufacturer)
            
            return {
                'manufacturers': manufacturers,
                'total': total,
                'pages': pages
            }
            
        except Exception as e:
            logger.error(f"Error getting pending manufacturers: {e}")
            return {'manufacturers': [], 'total': 0, 'pages': 0}
    
    @staticmethod
    def get_authorized_manufacturers_paginated(page=1, per_page=50, search=''):
        """Get paginated list of authorized manufacturers"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Base query
            query = {
                'role': 'manufacturer',
                'blockchain_status': 'verified'
            }
            
            # Add search filter if provided
            if search:
                search_regex = {'$regex': search, '$options': 'i'}
                query['$or'] = [
                    {'username': search_regex},
                    {'email': search_regex},
                    {'business_name': search_regex},
                    {'wallet_address': search_regex}
                ]
            
            # Get total count
            total = db_instance.users.count_documents(query)
            pages = ceil(total / per_page)
            
            # Get paginated results
            skip = (page - 1) * per_page
            manufacturers_cursor = db_instance.users.find(query).skip(skip).limit(per_page)
            
            manufacturers = []
            for manufacturer in manufacturers_cursor:
                manufacturer['id'] = str(manufacturer['_id'])
                del manufacturer['_id']
                # Remove sensitive fields
                manufacturer.pop('password_hash', None)
                manufacturers.append(manufacturer)
            
            return {
                'manufacturers': manufacturers,
                'total': total,
                'pages': pages
            }
            
        except Exception as e:
            logger.error(f"Error getting authorized manufacturers: {e}")
            return {'manufacturers': [], 'total': 0, 'pages': 0}
    
    @staticmethod
    def get_manufacturers_by_ids(manufacturer_ids):
        """Get manufacturer details by a list of IDs"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Convert string IDs to ObjectIds
            object_ids = []
            for mid in manufacturer_ids:
                if isinstance(mid, str):
                    object_ids.append(ObjectId(mid))
                else:
                    object_ids.append(mid)
            
            manufacturers_cursor = db_instance.users.find({
                '_id': {'$in': object_ids},
                'role': 'manufacturer'
            })
            
            manufacturers = []
            for manufacturer in manufacturers_cursor:
                manufacturer['id'] = str(manufacturer['_id'])
                del manufacturer['_id']
                # Only return essential fields
                essential_data = {
                    'id': manufacturer['id'],
                    'business_name': manufacturer.get('business_name'),
                    'wallet_address': manufacturer.get('wallet_address'),
                    'blockchain_status': manufacturer.get('blockchain_status')
                }
                manufacturers.append(essential_data)
            
            return manufacturers
            
        except Exception as e:
            logger.error(f"Error getting manufacturers by IDs: {e}")
            return []
    
    @staticmethod
    def update_manufacturers_blockchain_status(manufacturer_ids, status, admin_email, tx_hash=None):
        """Update blockchain status for multiple manufacturers"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Convert string IDs to ObjectIds
            object_ids = []
            for mid in manufacturer_ids:
                if isinstance(mid, str):
                    object_ids.append(ObjectId(mid))
                else:
                    object_ids.append(mid)
            
            # Prepare update document
            update_doc = {
                '$set': {
                    'blockchain_status': status,
                    'updated_at': datetime.utcnow().isoformat()
                }
            }
            
            # Add authorization fields if status is verified
            if status == 'verified':
                update_doc['$set'].update({
                    'authorized_at': datetime.utcnow().isoformat(),
                    'authorized_by': admin_email,
                    'authorization_tx_hash': tx_hash
                })
            
            # Update multiple documents
            result = db_instance.users.update_many(
                {'_id': {'$in': object_ids}},
                update_doc
            )
            
            logger.info(f"Updated blockchain status to '{status}' for {result.modified_count} manufacturers")
            
            return {
                'success': True,
                'updated_count': result.modified_count
            }
            
        except Exception as e:
            logger.error(f"Error updating manufacturer blockchain status: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def update_manufacturer_blockchain_status(manufacturer_id, status, admin_email, tx_hash=None):
        """Update blockchain status for a single manufacturer"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Convert to ObjectId if it's a string
            if isinstance(manufacturer_id, str):
                manufacturer_id = ObjectId(manufacturer_id)
            
            # Prepare update document
            update_doc = {
                '$set': {
                    'blockchain_status': status,
                    'updated_at': datetime.utcnow().isoformat()
                }
            }
            
            # Add authorization fields if status is verified
            if status == 'verified':
                update_doc['$set'].update({
                    'authorized_at': datetime.utcnow().isoformat(),
                    'authorized_by': admin_email,
                    'authorization_tx_hash': tx_hash
                })
            
            # Update the document
            result = db_instance.users.update_one(
                {'_id': manufacturer_id},
                update_doc
            )
            
            logger.info(f"Updated blockchain status to '{status}' for manufacturer {manufacturer_id}")
            
            return {
                'success': True,
                'manufacturer_id': str(manufacturer_id),
                'modified_count': result.modified_count
            }
            
        except Exception as e:
            logger.error(f"Error updating manufacturer {manufacturer_id} blockchain status: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    def log_admin_action(admin_id, admin_email, action, details=None):
        """Log admin actions for audit trail"""
        try:
            db_instance = AuthService.get_db_instance()
            
            audit_log = {
                'admin_id': ObjectId(admin_id) if isinstance(admin_id, str) else admin_id,
                'admin_email': admin_email,
                'action': action,
                'details': details,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'success'
            }
            
            db_instance.audit_logs.insert_one(audit_log)
            
            logger.info(f"Admin action logged: {action} by {admin_email}")
            
        except Exception as e:
            logger.error(f"Error logging admin action: {e}")
    
    @staticmethod
    def get_admin_audit_logs_paginated(page=1, per_page=50, action_filter='', date_from='', date_to=''):
        """Get paginated admin audit logs"""
        try:
            db_instance = AuthService.get_db_instance()
            
            # Build query
            query = {}
            
            # Action filter
            if action_filter:
                query['action'] = {'$regex': action_filter, '$options': 'i'}
            
            # Date range filter
            if date_from or date_to:
                date_query = {}
                if date_from:
                    try:
                        from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                        date_query['$gte'] = from_date.isoformat()
                    except ValueError:
                        logger.warning(f"Invalid date_from format: {date_from}")
                
                if date_to:
                    try:
                        to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                        date_query['$lte'] = to_date.isoformat()
                    except ValueError:
                        logger.warning(f"Invalid date_to format: {date_to}")
                
                if date_query:
                    query['timestamp'] = date_query
            
            # Get total count
            total = db_instance.audit_logs.count_documents(query)
            pages = ceil(total / per_page)
            
            # Get paginated results (sorted by timestamp descending)
            skip = (page - 1) * per_page
            logs_cursor = db_instance.audit_logs.find(query).sort('timestamp', -1).skip(skip).limit(per_page)
            
            logs = []
            for log in logs_cursor:
                log['id'] = str(log['_id'])
                del log['_id']
                # Convert admin_id to string if it's ObjectId
                if 'admin_id' in log and isinstance(log['admin_id'], ObjectId):
                    log['admin_id'] = str(log['admin_id'])
                logs.append(log)
            
            return {
                'logs': logs,
                'total': total,
                'pages': pages
            }
            
        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            return {'logs': [], 'total': 0, 'pages': 0}