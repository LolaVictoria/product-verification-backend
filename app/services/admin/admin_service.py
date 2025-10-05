# services/admin_service.py
import logging
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, Any
from app.config.database import get_db_connection
from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)

class AdminService:
    db = get_db_connection()

    def list_all_manufacturers(self) -> Dict[str, Any]:
        """List all manufacturers with their basic info and stats"""
        try:
            manufacturers = list(self.db.users.find(
                {'role': 'manufacturer'},
                {
                    '_id': 1,
                    'current_company_name': 1,
                    'primary_email': 1,
                    'verification_status': 1,
                    'account_status': 1,
                    'registration_date': 1,
                    'last_login': 1
                }
            ).sort('registration_date', -1))
            
            # Get product counts for each manufacturer
            for manufacturer in manufacturers:
                product_count = self.db.products.count_documents({
                    'manufacturer_id': manufacturer['_id']
                })
                manufacturer['product_count'] = product_count
                manufacturer['_id'] = str(manufacturer['_id'])
            
            return {
                'manufacturers': manufacturers,
                'total': len(manufacturers)
            }
            
        except Exception as e:
            logger.error(f"Error listing manufacturers: {e}")
            raise
    
    def get_manufacturer_admin_stats(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get detailed manufacturer statistics for admin"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Get manufacturer info
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Get product statistics
            total_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id
            })
            
            verified_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'blockchain_status': 'confirmed'
            })
            
            pending_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'blockchain_status': 'pending'
            })
            
            # Get verification statistics (last 30 days)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            
            recent_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            counterfeit_detections = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'result': 'counterfeit',
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            # Get API usage statistics
            api_keys = list(self.db.api_keys.find({
                'manufacturer_id': manufacturer_obj_id,
                'revoked': False
            }))
            
            api_usage = self.db.api_usage_logs.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })
            
            return {
                'success': True,
                'data': {
                    'manufacturer_info': {
                        '_id': str(manufacturer['_id']),
                        'current_company_name': manufacturer.get('current_company_name'),
                        'primary_email': manufacturer.get('primary_email'),
                        'verification_status': manufacturer.get('verification_status'),
                        'account_status': manufacturer.get('account_status'),
                        'registration_date': manufacturer.get('registration_date'),
                        'last_login': manufacturer.get('last_login')
                    },
                    'product_stats': {
                        'total_products': total_products,
                        'verified_products': verified_products,
                        'pending_products': pending_products
                    },
                    'verification_stats': {
                        'recent_verifications': recent_verifications,
                        'counterfeit_detections': counterfeit_detections,
                        'detection_rate': (counterfeit_detections / recent_verifications * 100) if recent_verifications > 0 else 0
                    },
                    'api_stats': {
                        'active_api_keys': len(api_keys),
                        'api_usage_30d': api_usage
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer admin stats: {e}")
            return {'success': False, 'message': 'Failed to get manufacturer stats'}
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get system health information"""
        try:
            # Database connection health
            db_healthy = True
            try:
                self.db.admin.command('ping')
            except:
                db_healthy = False
            
            # Get system statistics
            total_manufacturers = self.db.users.count_documents({'role': 'manufacturer'})
            verified_manufacturers = self.db.users.count_documents({
                'role': 'manufacturer',
                'verification_status': 'verified'
            })
            
            total_products = self.db.products.count_documents({})
            total_verifications = self.db.verification_logs.count_documents({})
            
            # Recent activity (last 24 hours)
            twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_verifications = self.db.verification_logs.count_documents({
                'timestamp': {'$gte': twenty_four_hours_ago}
            })
            
            recent_registrations = self.db.products.count_documents({
                'created_at': {'$gte': twenty_four_hours_ago}
            })
            
            # Error rates
            recent_failed_verifications = self.db.verification_logs.count_documents({
                'timestamp': {'$gte': twenty_four_hours_ago},
                'status': 'error'
            })
            
            error_rate = (recent_failed_verifications / recent_verifications * 100) if recent_verifications > 0 else 0
            
            return {
                'database': {
                    'status': 'healthy' if db_healthy else 'unhealthy',
                    'connection': db_healthy
                },
                'statistics': {
                    'total_manufacturers': total_manufacturers,
                    'verified_manufacturers': verified_manufacturers,
                    'total_products': total_products,
                    'total_verifications': total_verifications
                },
                'recent_activity': {
                    'verifications_24h': recent_verifications,
                    'registrations_24h': recent_registrations,
                    'error_rate': round(error_rate, 2)
                },
                'system_status': 'healthy' if db_healthy and error_rate < 5 else 'warning' if error_rate < 10 else 'critical',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {
                'system_status': 'critical',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def get_all_counterfeit_reports(self, page: int = 1, limit: int = 50, status: str = None) -> Dict[str, Any]:
        """Get all counterfeit reports with pagination"""
        try:
            skip = (page - 1) * limit
            
            # Build filter
            filter_dict = {'result': 'counterfeit'}
            if status:
                filter_dict['status'] = status
            
            # Get reports
            reports = list(self.db.verification_logs.find(
                filter_dict,
                {
                    'serial_number': 1,
                    'product': 1,
                    'timestamp': 1,
                    'ip_address': 1,
                    'user_agent': 1,
                    'source': 1,
                    'status': 1
                }
            ).sort('timestamp', -1).skip(skip).limit(limit))
            
            # Get total count
            total = self.db.verification_logs.count_documents(filter_dict)
            
            # Convert ObjectIds to strings
            for report in reports:
                report['_id'] = str(report['_id'])
            
            return {
                'reports': reports,
                'total': total,
                'page': page,
                'limit': limit,
                'pages': (total + limit - 1) // limit
            }
            
        except Exception as e:
            logger.error(f"Error getting counterfeit reports: {e}")
            return {
                'reports': [],
                'total': 0,
                'page': page,
                'limit': limit,
                'pages': 0,
                'error': str(e)
            }
    
    def verify_manufacturer(self, manufacturer_id: str, admin_user_id: str) -> Dict[str, Any]:
        """Verify a manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Update verification status
            update_result = self.db.users.update_one(
                {'_id': manufacturer_obj_id},
                {
                    '$set': {
                        'verification_status': 'verified',
                        'verified_at': datetime.now(timezone.utc),
                        'verified_by': ObjectId(admin_user_id)
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {'success': False, 'message': 'Failed to update manufacturer'}
            
            # Log the action
            self.log_admin_action(admin_user_id, 'verify_manufacturer', {
                'manufacturer_id': manufacturer_id,
                'manufacturer_name': manufacturer.get('current_company_name')
            })
            
            # Send notification
            notification_service.notify_manufacturer_verification(manufacturer_id, 'verified')
            
            return {
                'success': True,
                'message': 'Manufacturer verified successfully'
            }
            
        except Exception as e:
            logger.error(f"Error verifying manufacturer: {e}")
            return {'success': False, 'message': 'Failed to verify manufacturer'}
    
    def revoke_manufacturer_verification(self, manufacturer_id: str, admin_user_id: str) -> Dict[str, Any]:
        """Revoke manufacturer verification"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Update verification status
            update_result = self.db.users.update_one(
                {'_id': manufacturer_obj_id},
                {
                    '$set': {
                        'verification_status': 'revoked',
                        'revoked_at': datetime.now(timezone.utc),
                        'revoked_by': ObjectId(admin_user_id)
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {'success': False, 'message': 'Failed to update manufacturer'}
            
            # Log the action
            self.log_admin_action(admin_user_id, 'revoke_manufacturer', {
                'manufacturer_id': manufacturer_id,
                'manufacturer_name': manufacturer.get('current_company_name')
            })
            
            # Send notification
            notification_service.notify_manufacturer_verification(manufacturer_id, 'revoked')
            
            return {
                'success': True,
                'message': 'Manufacturer verification revoked successfully'
            }
            
        except Exception as e:
            logger.error(f"Error revoking manufacturer verification: {e}")
            return {'success': False, 'message': 'Failed to revoke manufacturer verification'}
    
    def suspend_manufacturer(self, manufacturer_id: str, admin_user_id: str, reason: str) -> Dict[str, Any]:
        """Suspend manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Update account status
            update_result = self.db.users.update_one(
                {'_id': manufacturer_obj_id},
                {
                    '$set': {
                        'account_status': 'suspended',
                        'suspended_at': datetime.now(timezone.utc),
                        'suspended_by': ObjectId(admin_user_id),
                        'suspension_reason': reason
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {'success': False, 'message': 'Failed to suspend manufacturer'}
            
            # Log the action
            self.log_admin_action(admin_user_id, 'suspend_manufacturer', {
                'manufacturer_id': manufacturer_id,
                'manufacturer_name': manufacturer.get('current_company_name'),
                'reason': reason
            })
            
            return {
                'success': True,
                'message': 'Manufacturer suspended successfully'
            }
            
        except Exception as e:
            logger.error(f"Error suspending manufacturer: {e}")
            return {'success': False, 'message': 'Failed to suspend manufacturer'}
    
    def activate_manufacturer(self, manufacturer_id: str, admin_user_id: str) -> Dict[str, Any]:
        """Activate suspended manufacturer account"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}
            
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Check if manufacturer exists
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}
            
            # Update account status
            update_result = self.db.users.update_one(
                {'_id': manufacturer_obj_id},
                {
                    '$set': {
                        'account_status': 'active',
                        'activated_at': datetime.now(timezone.utc),
                        'activated_by': ObjectId(admin_user_id)
                    },
                    '$unset': {
                        'suspended_at': '',
                        'suspended_by': '',
                        'suspension_reason': ''
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {'success': False, 'message': 'Failed to activate manufacturer'}
            
            # Log the action
            self.log_admin_action(admin_user_id, 'activate_manufacturer', {
                'manufacturer_id': manufacturer_id,
                'manufacturer_name': manufacturer.get('current_company_name')
            })
            
            return {
                'success': True,
                'message': 'Manufacturer activated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error activating manufacturer: {e}")
            return {'success': False, 'message': 'Failed to activate manufacturer'}
    
    def get_system_analytics(self, time_period: str = '7d') -> Dict[str, Any]:
        """Get system analytics for specified time period"""
        try:
            # Parse time period
            if time_period == '24h':
                start_date = datetime.now(timezone.utc) - timedelta(hours=24)
            elif time_period == '7d':
                start_date = datetime.now(timezone.utc) - timedelta(days=7)
            elif time_period == '30d':
                start_date = datetime.now(timezone.utc) - timedelta(days=30)
            elif time_period == '90d':
                start_date = datetime.now(timezone.utc) - timedelta(days=90)
            else:
                start_date = datetime.now(timezone.utc) - timedelta(days=7)
            
            # Verification analytics
            verification_pipeline = [
                {'$match': {'timestamp': {'$gte': start_date}}},
                {'$group': {
                    '_id': {
                        'date': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                        'result': '$result'
                    },
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id.date': 1}}
            ]
            
            verification_data = list(self.db.verification_logs.aggregate(verification_pipeline))
            
            # Product registration analytics
            product_pipeline = [
                {'$match': {'created_at': {'$gte': start_date}}},
                {'$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id': 1}}
            ]
            
            product_data = list(self.db.products.aggregate(product_pipeline))
            
            # Manufacturer registration analytics
            manufacturer_pipeline = [
                {'$match': {
                    'role': 'manufacturer',
                    'registration_date': {'$gte': start_date}
                }},
                {'$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$registration_date'}},
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id': 1}}
            ]
            
            manufacturer_data = list(self.db.users.aggregate(manufacturer_pipeline))
            
            # Top manufacturers by verification volume
            top_manufacturers_pipeline = [
                {'$match': {'timestamp': {'$gte': start_date}}},
                {'$group': {
                    '_id': '$product.manufacturer_id',
                    'verification_count': {'$sum': 1},
                    'counterfeit_count': {
                        '$sum': {'$cond': [{'$eq': ['$result', 'counterfeit']}, 1, 0]}
                    }
                }},
                {'$sort': {'verification_count': -1}},
                {'$limit': 10}
            ]
            
            top_manufacturers_raw = list(self.db.verification_logs.aggregate(top_manufacturers_pipeline))
            
            # Get manufacturer names
            top_manufacturers = []
            for item in top_manufacturers_raw:
                if item['_id']:
                    manufacturer = self.db.users.find_one(
                        {'_id': item['_id']},
                        {'current_company_name': 1}
                    )
                    if manufacturer:
                        item['manufacturer_name'] = manufacturer.get('current_company_name', 'Unknown')
                        top_manufacturers.append(item)
            
            return {
                'time_period': time_period,
                'verification_trends': verification_data,
                'product_registration_trends': product_data,
                'manufacturer_registration_trends': manufacturer_data,
                'top_manufacturers': top_manufacturers,
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting system analytics: {e}")
            return {
                'error': str(e),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
    
    def get_audit_logs(self, page: int = 1, limit: int = 50, action_type: str = None, user_id: str = None) -> Dict[str, Any]:
        """Get audit logs with pagination and filtering"""
        try:
            skip = (page - 1) * limit
            
            # Build filter
            filter_dict = {}
            if action_type:
                filter_dict['action_type'] = action_type
            if user_id and ObjectId.is_valid(user_id):
                filter_dict['admin_user_id'] = ObjectId(user_id)
            
            # Get logs
            logs = list(self.db.admin_audit_logs.find(
                filter_dict
            ).sort('timestamp', -1).skip(skip).limit(limit))
            
            # Get total count
            total = self.db.admin_audit_logs.count_documents(filter_dict)
            
            # Convert ObjectIds to strings and get admin user names
            for log in logs:
                log['_id'] = str(log['_id'])
                log['admin_user_id'] = str(log['admin_user_id'])
                
                # Get admin user name
                admin_user = self.db.users.find_one(
                    {'_id': ObjectId(log['admin_user_id'])},
                    {'username': 1, 'email': 1}
                )
                if admin_user:
                    log['admin_username'] = admin_user.get('username') or admin_user.get('email', 'Unknown')
                else:
                    log['admin_username'] = 'Unknown'
            
            return {
                'logs': logs,
                'total': total,
                'page': page,
                'limit': limit,
                'pages': (total + limit - 1) // limit
            }
            
        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            return {
                'logs': [],
                'total': 0,
                'page': page,
                'limit': limit,
                'pages': 0,
                'error': str(e)
            }
    
    def log_admin_action(self, admin_user_id: str, action_type: str, details: Dict[str, Any]):
        """Log admin action for audit purposes"""
        try:
            log_entry = {
                'admin_user_id': ObjectId(admin_user_id),
                'action_type': action_type,
                'details': details,
                'timestamp': datetime.now(timezone.utc)
            }
            
            self.db.admin_audit_logs.insert_one(log_entry)
            
        except Exception as e:
            logger.error(f"Error logging admin action: {e}")


admin_service = AdminService()