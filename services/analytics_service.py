# services/analytics_service.py
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from typing import Dict
from utils.date_utils import get_date_range, get_time_range_label
from config.__init__ import DatabaseConfig

class AnalyticsService:
    """Service for handling analytics calculations and data aggregation"""
    
    def __init__(self):
        self.db = DatabaseConfig.get_db_connection()
        self.users_collection = self.db.users
        self.products_collection = self.db.products
        self.verifications_collection = self.db.verifications
        self.counterfeit_reports_collection = self.db.counterfeit_reports
    
    def get_manufacturer_overview(self, manufacturer_id: str, time_range: str = '30d') -> Dict:
        """Get comprehensive manufacturer analytics overview"""
        try:
            start_date, end_date = get_date_range(time_range)
            
            # Get manufacturer products first
            manufacturer_products = list(self.products_collection.find(
                {'manufacturer_id': ObjectId(manufacturer_id)}, 
                {'_id': 1}
            ))
            product_ids = [p['_id'] for p in manufacturer_products]
            
            # Build match criteria for verifications
            match_criteria = {
                'created_at': {'$gte': start_date, '$lte': end_date}
            }
            
            if product_ids:
                match_criteria['$or'] = [
                    {'product_id': {'$in': product_ids}},
                    {'manufacturer_id': ObjectId(manufacturer_id)}
                ]
            else:
                match_criteria['manufacturer_id'] = ObjectId(manufacturer_id)
            
            # Aggregation pipeline for verification statistics
            pipeline = [
                {'$match': match_criteria},
                {
                    '$group': {
                        '_id': None,
                        'total_attempts': {'$sum': 1},
                        'successful_verifications': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                        },
                        'total_counterfeit': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                        },
                        'avg_response_time': {'$avg': '$response_time'},
                        'successful_transactions': {
                            '$sum': {'$cond': [{'$eq': ['$transaction_success', True]}, 1, 0]}
                        },
                        'avg_confidence': {'$avg': '$confidence_score'},
                        'unique_customers': {'$addToSet': '$customer_id'}
                    }
                }
            ]
            
            result = list(self.verifications_collection.aggregate(pipeline))
            
            if result:
                stats = result[0]
                total_attempts = stats['total_attempts']
                successful_verifications = stats['successful_verifications']
                total_counterfeit = stats['total_counterfeit']
                
                # Calculate KPIs with safe division
                verification_accuracy = (successful_verifications / total_attempts * 100) if total_attempts > 0 else 0
                counterfeit_rate = (total_counterfeit / total_attempts * 100) if total_attempts > 0 else 0
                transaction_efficiency = (stats['successful_transactions'] / total_attempts * 100) if total_attempts > 0 else 0
                
                return {
                    'kpis': {
                        'totalAttempts': total_attempts,
                        'successfulVerifications': successful_verifications,
                        'totalCounterfeit': total_counterfeit,
                        'verificationAccuracy': round(verification_accuracy, 1),
                        'counterfeitRate': round(counterfeit_rate, 1),
                        'avgResponseTime': round(stats['avg_response_time'] or 0, 2),
                        'transactionEfficiency': round(transaction_efficiency, 1),
                        'avgConfidenceScore': round(stats['avg_confidence'] or 0, 1),
                        'uniqueCustomers': len(stats['unique_customers'])
                    },
                    'dateRange': {
                        'start': start_date.isoformat(),
                        'end': end_date.isoformat(),
                        'label': get_time_range_label(time_range)
                    }
                }
            else:
                # Return empty stats if no data found
                return {
                    'kpis': {
                        'totalAttempts': 0,
                        'successfulVerifications': 0,
                        'totalCounterfeit': 0,
                        'verificationAccuracy': 0,
                        'counterfeitRate': 0,
                        'avgResponseTime': 0,
                        'transactionEfficiency': 0,
                        'avgConfidenceScore': 0,
                        'uniqueCustomers': 0
                    },
                    'dateRange': {
                        'start': start_date.isoformat(),
                        'end': end_date.isoformat(),
                        'label': get_time_range_label(time_range)
                    }
                }
                
        except Exception as e:
            raise Exception(f"Error getting manufacturer overview: {str(e)}")
    
    def get_verification_trends(self, manufacturer_id: str, time_range: str = '30d') -> Dict:
        """Get daily verification trends for manufacturer"""
        try:
            start_date, end_date = get_date_range(time_range)
            
            # Get manufacturer products
            manufacturer_products = list(self.products_collection.find(
                {'manufacturer_id': ObjectId(manufacturer_id)}, 
                {'_id': 1}
            ))
            product_ids = [p['_id'] for p in manufacturer_products]
            
            # Build match criteria
            match_criteria = {
                'created_at': {'$gte': start_date, '$lte': end_date}
            }
            
            if product_ids:
                match_criteria['$or'] = [
                    {'product_id': {'$in': product_ids}},
                    {'manufacturer_id': ObjectId(manufacturer_id)}
                ]
            else:
                match_criteria['manufacturer_id'] = ObjectId(manufacturer_id)
            
            # Daily aggregation pipeline
            pipeline = [
                {'$match': match_criteria},
                {
                    '$group': {
                        '_id': {
                            '$dateToString': {
                                'format': '%Y-%m-%d',
                                'date': '$created_at'
                            }
                        },
                        'total_attempts': {'$sum': 1},
                        'successful': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                        },
                        'counterfeit': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                        },
                        'avg_response_time': {'$avg': '$response_time'},
                        'avg_confidence': {'$avg': '$confidence_score'}
                    }
                },
                {'$sort': {'_id': 1}}
            ]
            
            daily_stats = list(self.verifications_collection.aggregate(pipeline))
            
            verification_trends = []
            for stat in daily_stats:
                verification_trends.append({
                    'date': stat['_id'],
                    'totalAttempts': stat['total_attempts'],
                    'successful': stat['successful'],
                    'counterfeit': stat['counterfeit'],
                    'responseTime': round(stat['avg_response_time'] or 0, 2),
                    'confidence': round(stat['avg_confidence'] or 0, 1)
                })
            
            return {'verificationTrends': verification_trends}
            
        except Exception as e:
            raise Exception(f"Error getting verification trends: {str(e)}")
    
    def get_device_analytics(self, manufacturer_id: str, time_range: str = '30d') -> Dict:
        """Get device analytics for manufacturer"""
        try:
            start_date, end_date = get_date_range(time_range)
            recent_threshold = datetime.now(timezone.utc) - timedelta(days=7)
            
            # Get manufacturer products
            manufacturer_products = list(self.products_collection.find(
                {'manufacturer_id': ObjectId(manufacturer_id)}, 
                {'_id': 1, 'device_type': 1, 'brand': 1, 'model': 1}
            ))
            product_ids = [p['_id'] for p in manufacturer_products]
            
            if not product_ids:
                return {'deviceVerifications': []}
            
            # Build match criteria
            match_criteria = {
                'created_at': {'$gte': start_date, '$lte': end_date},
                '$or': [
                    {'product_id': {'$in': product_ids}},
                    {'manufacturer_id': ObjectId(manufacturer_id)}
                ]
            }
            
            # Device analytics pipeline
            pipeline = [
                {'$match': match_criteria},
                {
                    '$lookup': {
                        'from': 'products',
                        'localField': 'product_id',
                        'foreignField': '_id',
                        'as': 'product'
                    }
                },
                {
                    '$lookup': {
                        'from': 'counterfeit_reports',
                        'localField': '_id',
                        'foreignField': 'verification_id',
                        'as': 'counterfeit_report'
                    }
                },
                {
                    '$addFields': {
                        'product_data': {'$arrayElemAt': ['$product', 0]},
                        'counterfeit_report_data': {'$arrayElemAt': ['$counterfeit_report', 0]},
                        'final_device_category': {
                            '$switch': {
                                'branches': [
                                    {
                                        'case': {'$ne': ['$device_category', None]},
                                        'then': '$device_category'
                                    },
                                    {
                                        'case': {'$ne': ['$product_data.device_type', None]},
                                        'then': '$product_data.device_type'
                                    },
                                    {
                                        'case': {'$ne': ['$counterfeit_report_data.device_category', None]},
                                        'then': '$counterfeit_report_data.device_category'
                                    }
                                ],
                                'default': 'Unknown'
                            }
                        }
                    }
                },
                {
                    '$group': {
                        '_id': '$final_device_category',
                        'total_verifications': {'$sum': 1},
                        'authentic': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                        },
                        'counterfeit': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                        },
                        'unique_customers': {'$addToSet': '$customer_id'},
                        'avg_confidence': {'$avg': '$confidence_score'},
                        'recent_verifications': {
                            '$sum': {
                                '$cond': [
                                    {'$gte': ['$created_at', recent_threshold]},
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                },
                {
                    '$addFields': {
                        'customer_count': {'$size': '$unique_customers'},
                        'authenticity_rate': {
                            '$multiply': [
                                {'$divide': ['$authentic', '$total_verifications']},
                                100
                            ]
                        }
                    }
                },
                {'$sort': {'total_verifications': -1}}
            ]
            
            device_stats = list(self.verifications_collection.aggregate(pipeline))
            
            colors = ['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6', '#EC4899', '#6B7280']
            
            device_verifications = []
            for i, stat in enumerate(device_stats):
                device_name = stat['_id'] if stat['_id'] and stat['_id'] != 'Unknown' else 'Unknown Device'
                device_verifications.append({
                    'name': device_name,
                    'verifications': stat['total_verifications'],
                    'authentic': stat['authentic'],
                    'counterfeit': stat['counterfeit'],
                    'color': colors[i % len(colors)],
                    'customerCount': stat['customer_count'],
                    'authenticityRate': round(stat['authenticity_rate'], 1),
                    'avgConfidence': round(stat['avg_confidence'] or 0, 1),
                    'recentVerifications': stat['recent_verifications']
                })
            
            return {'deviceVerifications': device_verifications}
            
        except Exception as e:
            raise Exception(f"Error getting device analytics: {str(e)}")
    
    def get_verification_logs(self, manufacturer_id: str, limit: int = 50, time_range: str = '30d') -> Dict:
        """Get manufacturer's verification logs"""
        try:
            start_date, end_date = get_date_range(time_range)
            
            # Enhanced pipeline to get verification logs for manufacturer
            pipeline = [
                {
                    '$match': {
                        'manufacturer_id': ObjectId(manufacturer_id),
                        'created_at': {'$gte': start_date}
                    }
                },
                {
                    '$lookup': {
                        'from': 'counterfeit_reports',
                        'localField': '_id',
                        'foreignField': 'verification_id',
                        'as': 'counterfeit_report'
                    }
                },
                {
                    '$lookup': {
                        'from': 'products',
                        'localField': 'product_id',
                        'foreignField': '_id',
                        'as': 'product'
                    }
                },
                {
                    '$lookup': {
                        'from': 'users',
                        'localField': 'customer_id',
                        'foreignField': '_id',
                        'as': 'customer'
                    }
                },
                {
                    '$addFields': {
                        'counterfeit_report_data': {'$arrayElemAt': ['$counterfeit_report', 0]},
                        'product_data': {'$arrayElemAt': ['$product', 0]},
                        'customer_data': {'$arrayElemAt': ['$customer', 0]}
                    }
                },
                {
                    '$addFields': {
                        'final_device_name': {
                            '$switch': {
                                'branches': [
                                    {
                                        'case': {'$ne': ['$device_name', None]},
                                        'then': '$device_name'
                                    },
                                    {
                                        'case': {'$ne': ['$counterfeit_report_data.product_name', None]},
                                        'then': '$counterfeit_report_data.product_name'
                                    },
                                    {
                                        'case': {'$ne': ['$product_data', None]},
                                        'then': {
                                            '$concat': [
                                                {'$ifNull': ['$product_data.brand', '']},
                                                ' ',
                                                {'$ifNull': ['$product_data.model', '']}
                                            ]
                                        }
                                    }
                                ],
                                'default': 'Unknown Product'
                            }
                        },
                        'final_device_category': {
                            '$switch': {
                                'branches': [
                                    {
                                        'case': {'$ne': ['$device_category', None]},
                                        'then': '$device_category'
                                    },
                                    {
                                        'case': {'$ne': ['$counterfeit_report_data.device_category', None]},
                                        'then': '$counterfeit_report_data.device_category'
                                    },
                                    {
                                        'case': {'$ne': ['$product_data.device_type', None]},
                                        'then': '$product_data.device_type'
                                    }
                                ],
                                'default': 'Unknown Category'
                            }
                        }
                    }
                },
                {'$sort': {'created_at': -1}},
                {'$limit': limit}
            ]
            
            verifications = list(self.verifications_collection.aggregate(pipeline))
            
            verification_logs = []
            for verification in verifications:
                # Clean up device name if it's just spaces
                device_name = verification.get('final_device_name', 'Unknown Product').strip()
                if not device_name or device_name == ' ':
                    device_name = 'Unknown Product'
                
                # Get customer info
                customer_data = verification.get('customer_data', {})
                customer_name = customer_data.get('name', 'Unknown Customer')
                customer_email = customer_data.get('primary_email', 'Unknown Email')
                
                log_entry = {
                    'serialNumber': verification['serial_number'],
                    'deviceName': device_name,
                    'deviceCategory': verification.get('final_device_category', 'Unknown Category'),
                    'status': 'Authentic' if verification['is_authentic'] else 'Counterfeit',
                    'date': verification['created_at'].strftime('%Y-%m-%d'),
                    'time': f"{verification.get('response_time', 0):.2f}s",
                    'confidence': round(verification.get('confidence_score', 0), 1),
                    'verificationMethod': verification.get('verification_method', 'manual'),
                    'customerId': str(verification['customer_id']) if verification.get('customer_id') else None,
                    'customerName': customer_name,
                    'customerEmail': customer_email,
                    'verificationId': str(verification['_id'])
                }
                
                # Add counterfeit ID if this verification has a counterfeit report
                if verification.get('counterfeit_report_data'):
                    log_entry['counterfeitId'] = str(verification['counterfeit_report_data']['_id'])
                
                verification_logs.append(log_entry)
            
            return {'verificationLogs': verification_logs}
            
        except Exception as e:
            raise Exception(f"Error getting verification logs: {str(e)}")
    
    def get_customer_analytics(self, customer_id: str, time_range: str = '30d') -> Dict:
        """Get customer's personal analytics"""
        try:
            start_date, end_date = get_date_range(time_range)
            
            # Customer verification history
            history_pipeline = [
                {
                    '$match': {
                        'customer_id': ObjectId(customer_id),
                        'created_at': {'$gte': start_date}
                    }
                },
                {
                    '$group': {
                        '_id': {
                            '$dateToString': {
                                'format': '%Y-%m-%d',
                                'date': '$created_at'
                            }
                        },
                        'verifications': {'$sum': 1},
                        'authentic': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                        },
                        'counterfeit': {
                            '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                        },
                        'avg_time': {'$avg': '$response_time'}
                    }
                },
                {'$sort': {'_id': 1}}
            ]
            
            verification_history = list(self.verifications_collection.aggregate(history_pipeline))
            
            customer_history = []
            for history in verification_history:
                customer_history.append({
                    'date': history['_id'],
                    'verifications': history['verifications'],
                    'authentic': history['authentic'],
                    'counterfeit': history['counterfeit'],
                    'avgTime': round(history['avg_time'] or 0, 2)
                })
            
            return {'customerHistory': customer_history}
            
        except Exception as e:
            raise Exception(f"Error getting customer analytics: {str(e)}")
    
    def get_system_stats(self) -> Dict:
        """Get system-wide verification statistics"""
        try:
            # Count total products
            total_devices = self.products_collection.count_documents({})
            blockchain_devices = self.products_collection.count_documents({"blockchain_verified": True})
            
            # Count verification logs
            total_verifications = self.verifications_collection.count_documents({})
            
            # Calculate authenticity rate
            authentic_verifications = self.verifications_collection.count_documents({"is_authentic": True})
            authenticity_rate = int((authentic_verifications / total_verifications * 100)) if total_verifications > 0 else 0
            
            return {
                "total_devices": total_devices,
                "blockchain_devices": blockchain_devices,
                "total_verifications": total_verifications,
                "authenticity_rate": authenticity_rate
            }
            
        except Exception as e:
            return {
                "total_devices": 0,
                "blockchain_devices": 0,
                "total_verifications": 0,
                "authenticity_rate": 0
            }
    
    def record_verification_attempt(self, verification_data: Dict) -> str:
        """Record a verification attempt"""
        try:
            serial_number = verification_data.get('serialNumber')
            customer_id = verification_data.get('customerId')
            is_authentic = verification_data.get('isAuthentic', False)
            response_time = verification_data.get('responseTime', 0)
            confidence_score = verification_data.get('confidenceScore', 0)
            verification_method = verification_data.get('verificationMethod', 'manual')
            
            # Enhanced device information
            device_name = verification_data.get('deviceName', 'Unknown Product')
            device_category = verification_data.get('deviceCategory', 'Unknown Category')
            brand = verification_data.get('brand', 'Unknown Brand')
            
            # Find product if it exists
            product = None
            if is_authentic:
                product = self.products_collection.find_one({'serial_number': serial_number})
            
            verification_doc = {
                'serial_number': serial_number,
                'product_id': product['_id'] if product else None,
                'customer_id': ObjectId(customer_id) if customer_id else None,
                'manufacturer_id': product['manufacturer_id'] if product else None,
                'is_authentic': is_authentic,
                'confidence_score': confidence_score,
                'response_time': response_time,
                'transaction_success': is_authentic,
                'customer_satisfaction_rating': 5 if is_authentic else 2,
                'verification_method': verification_method,
                
                # Enhanced device information fields
                'device_name': device_name,
                'device_category': device_category,
                'brand': brand,
                
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            result = self.verifications_collection.insert_one(verification_doc)
            return str(result.inserted_id)
            
        except Exception as e:
            raise Exception(f"Error recording verification attempt: {str(e)}")

analytic_service = AnalyticsService