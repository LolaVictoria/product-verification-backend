#services/analytics_service
import logging
from bson import ObjectId
from app.config.database import get_db_connection
from app.utils.date_helpers import date_helper_utils
from datetime import  timedelta
from bson import ObjectId
from typing import Dict, Any
import pymongo
from app.config.database import get_db_connection
logger = logging.getLogger(__name__)

class AnalyticsService:
    def __init__(self):
        self.db = get_db_connection()
    
    @staticmethod
    def get_system_overview(self, time_range='7d'):
        """Get system-wide analytics overview"""
        try:
            start_date, end_date = date_helper_utils.date_helper_utils.get_date_rang(time_range)
            
            # Total counts
            total_products = self.db.products.count_documents({})
            total_manufacturers = self.db.users.count_documents({'role': 'manufacturer'})
            total_verifications = self.db.verifications.count_documents({})
            
            # Recent activity
            recent_products = self.db.products.count_documents({
                'created_at': {'$gte': start_date}
            })
            
            recent_verifications = self.db.verifications.count_documents({
                'timestamp': {'$gte': start_date}
            })
            
            recent_manufacturers = self.db.users.count_documents({
                'role': 'manufacturer',
                'created_at': {'$gte': start_date}
            })
            
            # Blockchain vs database products
            blockchain_products = self.db.products.count_documents({
                'registration_type': 'blockchain_confirmed'
            })
            
            database_products = total_products - blockchain_products
            
            # Success rates
            successful_verifications = self.db.verifications.count_documents({
                'result': 'authentic',
                'timestamp': {'$gte': start_date}
            })
            
            verification_success_rate = 0
            if recent_verifications > 0:
                verification_success_rate = (successful_verifications / recent_verifications) * 100
            
            overview = {
                'totals': {
                    'products': total_products,
                    'manufacturers': total_manufacturers,
                    'verifications': total_verifications
                },
                'recent_activity': {
                    'products': recent_products,
                    'manufacturers': recent_manufacturers,
                    'verifications': recent_verifications
                },
                'product_distribution': {
                    'blockchain': blockchain_products,
                    'database': database_products
                },
                'performance': {
                    'verification_success_rate': round(verification_success_rate, 1)
                }
            }
            
            return date_helper_utils.format_analytics_response([overview], time_range)
            
        except Exception as e:
            logger.error(f"Error getting system overview: {e}")
            raise
    
    @staticmethod
    def get_verification_analytics(self, time_range='7d', manufacturer_id=None):
        """Get verification analytics"""
        try:
            start_date, end_date = e(time_range)
            
            # Base query
            base_query = {'timestamp': {'$gte': start_date, '$lte': end_date}}
            
            # Filter by manufacturer if specified
            if manufacturer_id:
                manufacturer_products = list(self.db.products.find(
                    {'manufacturer_id': manufacturer_id},
                    {'serial_number': 1}
                ))
                serial_numbers = [p['serial_number'] for p in manufacturer_products]
                base_query['serial_number'] = {'$in': serial_numbers}
            
            # Verification statistics
            pipeline = [
                {'$match': base_query},
                {'$group': {
                    '_id': '$result',
                    'count': {'$sum': 1}
                }}
            ]
            
            verification_results = list(self.db.verifications.aggregate(pipeline))
            
            # Process results
            authentic_count = 0
            counterfeit_count = 0
            total_verifications = 0
            
            for result in verification_results:
                count = result['count']
                total_verifications += count
                
                if result['_id'] == 'authentic':
                    authentic_count = count
                elif result['_id'] == 'counterfeit':
                    counterfeit_count = count
            
            # Calculate rates
            authenticity_rate = (authentic_count / total_verifications * 100) if total_verifications > 0 else 0
            counterfeit_rate = (counterfeit_count / total_verifications * 100) if total_verifications > 0 else 0
            
            # Daily verification trends
            daily_pipeline = [
                {'$match': base_query},
                {'$group': {
                    '_id': {
                        'date': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                        'result': '$result'
                    },
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id.date': 1}}
            ]
            
            daily_data = list(self.db.verifications.aggregate(daily_pipeline))
            
            analytics = {
                'summary': {
                    'total_verifications': total_verifications,
                    'authentic_count': authentic_count,
                    'counterfeit_count': counterfeit_count,
                    'authenticity_rate': round(authenticity_rate, 1),
                    'counterfeit_rate': round(counterfeit_rate, 1)
                },
                'daily_trends': self._format_daily_trends(daily_data)
            }
            
            return date_helper_utils.format_analytics_response([analytics], time_range)
            
        except Exception as e:
            logger.error(f"Error getting verification analytics: {e}")
            raise
    
    @staticmethod
    def get_manufacturer_analytics(self, manufacturer_id, time_range='7d'):
        """Get analytics for specific manufacturer"""
        try:
            start_date, end_date = date_helper_utils.get_date_rang(time_range)
            
            # Get manufacturer info
            manufacturer = self.db.users.find_one({'_id': ObjectId(manufacturer_id)})
            if not manufacturer:
                raise ValueError("Manufacturer not found")
            
            # Product statistics
            total_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_id
            })
            
            recent_products = self.db.products.count_documents({
                'manufacturer_id': manufacturer_id,
                'created_at': {'$gte': start_date}
            })
            
            # Get product serial numbers for verification lookup
            manufacturer_products = list(self.db.products.find(
                {'manufacturer_id': manufacturer_id},
                {'serial_number': 1}
            ))
            serial_numbers = [p['serial_number'] for p in manufacturer_products]
            
            # Verification statistics
            if serial_numbers:
                total_verifications = self.db.verifications.count_documents({
                    'serial_number': {'$in': serial_numbers}
                })
                
                recent_verifications = self.db.verifications.count_documents({
                    'serial_number': {'$in': serial_numbers},
                    'timestamp': {'$gte': start_date}
                })
                
                authentic_verifications = self.db.verifications.count_documents({
                    'serial_number': {'$in': serial_numbers},
                    'result': 'authentic',
                    'timestamp': {'$gte': start_date}
                })
            else:
                total_verifications = recent_verifications = authentic_verifications = 0
            
            # Registration type breakdown
            registration_pipeline = [
                {'$match': {'manufacturer_id': manufacturer_id}},
                {'$group': {
                    '_id': '$registration_type',
                    'count': {'$sum': 1}
                }}
            ]
            
            registration_breakdown = list(self.db.products.aggregate(registration_pipeline))
            
            # Device type breakdown
            device_pipeline = [
                {'$match': {'manufacturer_id': manufacturer_id}},
                {'$group': {
                    '_id': '$device_type',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}},
                {'$limit': 10}
            ]
            
            device_breakdown = list(self.db.products.aggregate(device_pipeline))
            
            analytics = {
                'manufacturer_info': {
                    'id': manufacturer_id,
                    'company_name': manufacturer.get('current_company_name'),
                    'verification_status': manufacturer.get('verification_status')
                },
                'products': {
                    'total': total_products,
                    'recent': recent_products,
                    'registration_breakdown': registration_breakdown,
                    'device_breakdown': device_breakdown
                },
                'verifications': {
                    'total': total_verifications,
                    'recent': recent_verifications,
                    'authentic': authentic_verifications,
                    'success_rate': round((authentic_verifications / recent_verifications * 100) if recent_verifications > 0 else 0, 1)
                }
            }
            
            return date_helper_utils.format_analytics_response([analytics], time_range)
            
        except Exception as e:
            logger.error(f"Error getting manufacturer analytics: {e}")
            raise
    
    @staticmethod
    def get_product_performance(self, time_range='30d', limit=20):
        """Get top performing products by verification count"""
        try:
            start_date, end_date = date_helper_utils.get_date_rang(time_range)
            
            # Get verification counts per product
            pipeline = [
                {'$match': {'timestamp': {'$gte': start_date, '$lte': end_date}}},
                {'$group': {
                    '_id': '$serial_number',
                    'verification_count': {'$sum': 1},
                    'authentic_count': {
                        '$sum': {'$cond': [{'$eq': ['$result', 'authentic']}, 1, 0]}
                    },
                    'counterfeit_count': {
                        '$sum': {'$cond': [{'$eq': ['$result', 'counterfeit']}, 1, 0]}
                    }
                }},
                {'$sort': {'verification_count': -1}},
                {'$limit': limit}
            ]
            
            verification_stats = list(self.db.verifications.aggregate(pipeline))
            
            # Enhance with product details
            performance_data = []
            for stat in verification_stats:
                product = self.db.products.find_one({
                    'serial_number': stat['_id']
                })
                
                if product:
                    manufacturer = self.db.users.find_one({
                        '_id': ObjectId(product['manufacturer_id'])
                    })
                    
                    performance_data.append({
                        'serial_number': stat['_id'],
                        'product_name': f"{product.get('brand', '')} {product.get('model', '')}".strip(),
                        'manufacturer_name': manufacturer.get('current_company_name') if manufacturer else 'Unknown',
                        'verification_count': stat['verification_count'],
                        'authentic_count': stat['authentic_count'],
                        'counterfeit_count': stat['counterfeit_count'],
                        'authenticity_rate': round((stat['authentic_count'] / stat['verification_count'] * 100), 1)
                    })
            
            return date_helper_utils.format_analytics_response(performance_data, time_range)
            
        except Exception as e:
            logger.error(f"Error getting product performance: {e}")
            raise
    
    @staticmethod
    def get_geographic_analytics(self, time_range='30d'):
        """Get geographic distribution of verifications"""
        try:
            start_date, end_date = date_helper_utils.get_date_rang(time_range)
            
            # Group by country/region (based on IP if available)
            pipeline = [
                {'$match': {'timestamp': {'$gte': start_date, '$lte': end_date}}},
                {'$group': {
                    '_id': '$country',  # Assuming you store country from IP
                    'verification_count': {'$sum': 1},
                    'unique_ips': {'$addToSet': '$ip_address'}
                }},
                {'$project': {
                    'country': '$_id',
                    'verification_count': 1,
                    'unique_users': {'$size': '$unique_ips'}
                }},
                {'$sort': {'verification_count': -1}},
                {'$limit': 20}
            ]
            
            geographic_data = list(self.db.verifications.aggregate(pipeline))
            
            return date_helper_utils.format_analytics_response(geographic_data, time_range)
            
        except Exception as e:
            logger.error(f"Error getting geographic analytics: {e}")
            raise
    
    @staticmethod
    def _format_daily_trends(self, daily_data):
        """Format daily trend data"""
        trends = {}
        
        for entry in daily_data:
            date = entry['_id']['date']
            result = entry['_id']['result']
            count = entry['count']
            
            if date not in trends:
                trends[date] = {'authentic': 0, 'counterfeit': 0, 'total': 0}
            
            trends[date][result] = count
            trends[date]['total'] += count
        
        # Convert to list format
        formatted_trends = []
        for date, data in sorted(trends.items()):
            formatted_trends.append({
                'date': date,
                'authentic': data['authentic'],
                'counterfeit': data['counterfeit'],
                'total': data['total']
            })
        
        return formatted_trends

    @staticmethod
    def get_dashboard_stats(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get manufacturer dashboard statistics"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {'success': False, 'message': 'Invalid manufacturer ID'}

            manufacturer_obj_id = ObjectId(manufacturer_id)
            manufacturer = self.db.users.find_one({'_id': manufacturer_obj_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {'success': False, 'message': 'Manufacturer not found'}

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

            thirty_days_ago = date_helper_utils.date_helper_utils.get_current_utc() - timedelta(days=30)
            recent_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })
            successful_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'result': 'authentic',
                'timestamp': {'$gte': thirty_days_ago}
            })
            counterfeit_detections = self.db.verification_logs.count_documents({
                'product.manufacturer_id': manufacturer_obj_id,
                'result': 'counterfeit',
                'timestamp': {'$gte': thirty_days_ago}
            })

            active_api_keys = self.db.api_keys.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'revoked': False
            })
            api_usage_30d = self.db.api_usage_logs.count_documents({
                'manufacturer_id': manufacturer_obj_id,
                'timestamp': {'$gte': thirty_days_ago}
            })

            recent_products = list(self.db.products.find(
                {'manufacturer_id': manufacturer_obj_id},
                {'serial_number': 1, 'brand': 1, 'model': 1, 'created_at': 1, 'blockchain_status': 1}
            ).sort('created_at', -1).limit(5))
            for product in recent_products:
                product['_id'] = str(product['_id'])

            return {
                'success': True,
                'data': {
                    'product_stats': {
                        'total_products': total_products,
                        'verified_products': verified_products,
                        'pending_products': pending_products,
                        'verification_rate': (verified_products / total_products * 100) if total_products > 0 else 0
                    },
                    'verification_stats': {
                        'total_verifications': recent_verifications,
                        'successful_verifications': successful_verifications,
                        'counterfeit_detections': counterfeit_detections,
                        'success_rate': (successful_verifications / recent_verifications * 100) if recent_verifications > 0 else 0
                    },
                    'api_stats': {
                        'active_api_keys': active_api_keys,
                        'api_usage_30d': api_usage_30d
                    },
                    'recent_products': recent_products,
                    'account_info': {
                        'verification_status': manufacturer.get('verification_status'),
                        'account_status': manufacturer.get('account_status'),
                        'company_name': manufacturer.get('current_company_name')
                    }
                }
            }

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error getting dashboard stats: {str(e)}")
            return {'success': False, 'message': 'Failed to get dashboard stats'}
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {str(e)}")
            return {'success': False, 'message': 'Failed to get dashboard stats'}

    @staticmethod
    def get_manufacturer_analytics_api(self, manufacturer_id: str, time_range: str = '7d') -> Dict[str, Any]:
        """Get manufacturer analytics for API"""
        try:
            from app.utils.date_helpers import get_date_range
            start_date, end_date = get_date_range(time_range)

            total_products = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            recent_products = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id),
                'created_at': {'$gte': start_date}
            })

            verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': ObjectId(manufacturer_id),
                'timestamp': {'$gte': start_date}
            })
            successful_verifications = self.db.verification_logs.count_documents({
                'product.manufacturer_id': ObjectId(manufacturer_id),
                'result': 'authentic',
                'timestamp': {'$gte': start_date}
            })
            counterfeit_detections = self.db.verification_logs.count_documents({
                'product.manufacturer_id': ObjectId(manufacturer_id),
                'result': 'counterfeit',
                'timestamp': {'$gte': start_date}
            })

            return {
                'success': True,
                'data': {
                    'time_range': time_range,
                    'products': {
                        'total': total_products,
                        'recent': recent_products
                    },
                    'verifications': {
                        'total': verifications,
                        'successful': successful_verifications,
                        'counterfeit': counterfeit_detections,
                        'success_rate': (successful_verifications / verifications * 100) if verifications > 0 else 0
                    },
                    'generated_at': date_helper_utils.date_helper_utils.get_current_utc().isoformat()
                }
            }

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error getting analytics: {str(e)}")
            return {'success': False, 'message': 'Failed to get analytics'}
        except Exception as e:
            logger.error(f"Error getting analytics: {str(e)}")
            return {'success': False, 'message': 'Failed to get analytics'}


analytics_service = AnalyticsService()