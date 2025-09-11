from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient
from collections import defaultdict
from helper_functions import get_db_connection
from typing import Tuple, Optional 
import pytz

analytics_bp = Blueprint('analytics', __name__)
db = get_db_connection()

users_collection = db.users
products_collection = db.products
verifications_collection = db.verifications
counterfeit_reports_collection = db.counterfeit_reports



def get_date_range(time_range: str, end_date: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """
    Helper function to calculate date range for analytics queries.
    
    Args:
        time_range: String representing the time range ('7d', '30d', '90d', '1y')
        end_date: Optional end date (defaults to current UTC time)
    
    Returns:
        Tuple of (start_date, end_date) as datetime objects
        
    Raises:
        ValueError: If time_range format is invalid
    """
    if end_date is None:
        end_date = datetime.utcnow()
    
    # Ensure end_date is timezone-aware (UTC)
    if end_date.tzinfo is None:
        end_date = end_date.replace(tzinfo=pytz.UTC)
    
    # Time range mapping
    time_deltas = {
        '7d': 7,
        '14d': 14,
        '30d': 30,
        '90d': 90,
        '1y': 365,
        '6m': 180,  #6 months
        '3m': 90,   #3 months
        '1m': 30    #1 month
    }
    
    # Get days or default to 7
    days = time_deltas.get(time_range, 7)
    
    # Calculate start date
    start_date = end_date - timedelta(days=days)
    
    return start_date, end_date

def get_date_range_dict(time_range: str, end_date: Optional[datetime] = None) -> dict:
    """
    Return date range as serializable dictionary.
    
    Returns:
        Dict with start_date, end_date, and metadata
    """
    start_date, end_date = get_date_range(time_range, end_date)
    
    # FIX: Convert timedelta to integer days for JSON serialization
    days_count = (end_date - start_date).days
    
    return {
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'time_range': time_range,
        'days_count': days_count,  # Now it's an integer, not timedelta
        'range_label': get_time_range_label(time_range)
    }

def get_time_range_label(time_range: str) -> str:
    """Get human-readable label for time range"""
    labels = {
        '7d': 'Last 7 Days',
        '30d': 'Last 30 Days',
        '90d': 'Last 90 Days',
        '1y': 'Last Year',
        '6m': 'Last 6 Months',
        '3m': 'Last 3 Months',
        '1m': 'Last Month'
    }
    return labels.get(time_range, 'Last 7 Days')

# For database queries - returns just the start date
def get_start_date(time_range: str) -> datetime:
    """
    Get just the start date for database queries.
    Returns timezone-aware datetime.
    """
    start_date, _ = get_date_range(time_range)
    return start_date

# Validate time range
def is_valid_time_range(time_range: str) -> bool:
    """Check if time range is valid"""
    valid_ranges = ['7d', '30d', '90d', '1y', '6m', '3m', '1m']
    return time_range in valid_ranges

# MANUFACTURER ANALYTICS ROUTES

@analytics_bp.route('/analytics/manufacturer/overview', methods=['GET'])
def get_manufacturer_overview():
    """Get manufacturer analytics overview with KPIs"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        # Aggregation pipeline for comprehensive manufacturer analytics
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': ObjectId(manufacturer_id),
                    'created_at': {'$gte': start_date}
                }
            },
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
                    }
                }
            }
        ]
        
        result = list(verifications_collection.aggregate(pipeline))
        stats = result[0] if result else {
            'total_attempts': 0,
            'successful_verifications': 0,
            'total_counterfeit': 0,
            'avg_response_time': 0,
            'successful_transactions': 0
        }
        
        # Calculate KPIs
        total_attempts = stats['total_attempts']
        successful_verifications = stats['successful_verifications']
        total_counterfeit = stats['total_counterfeit']
        
        verification_accuracy = (successful_verifications / total_attempts * 100) if total_attempts > 0 else 0
        counterfeit_rate = (total_counterfeit / total_attempts * 100) if total_attempts > 0 else 0
        transaction_efficiency = (stats['successful_transactions'] / total_attempts * 100) if total_attempts > 0 else 0
        
        return jsonify({
            'kpis': {
                'totalAttempts': total_attempts,
                'successfulVerifications': successful_verifications,
                'totalCounterfeit': total_counterfeit,
                'verificationAccuracy': round(verification_accuracy, 1),
                'counterfeitRate': round(counterfeit_rate, 1),
                'avgResponseTime': round(stats['avg_response_time'] or 0, 2),
                'transactionEfficiency': round(transaction_efficiency, 1)
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/manufacturer/verification-trends', methods=['GET'])
def get_verification_trends():
    """Get daily verification trends"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': ObjectId(manufacturer_id),
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
                    'total_attempts': {'$sum': 1},
                    'successful': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    },
                    'avg_response_time': {'$avg': '$response_time'}
                }
            },
            {'$sort': {'_id': 1}}
        ]
        
        daily_stats = list(verifications_collection.aggregate(pipeline))
        
        verification_trends = []
        for stat in daily_stats:
            verification_trends.append({
                'date': stat['_id'],
                'totalAttempts': stat['total_attempts'],
                'successful': stat['successful'],
                'counterfeit': stat['counterfeit'],
                'responseTime': round(stat['avg_response_time'] or 0, 2)
            })

        return jsonify({'verificationTrends': verification_trends})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/manufacturer/device-analytics', methods=['GET'])
def get_manufacturer_device_analytics():
    """Enhanced manufacturer device analytics with comprehensive breakdown"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range) 
        
        # FIX: Calculate the recent date threshold outside the pipeline
        recent_threshold = datetime.utcnow() - timedelta(days=7)
        
        # Enhanced pipeline that looks at all verification sources
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': ObjectId(manufacturer_id),
                    'created_at': {'$gte': start_date}
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
                    # Determine device category with fallback logic
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
                    # Additional metrics for manufacturer insights
                    'unique_customers': {'$addToSet': '$customer_id'},
                    'avg_confidence': {'$avg': '$confidence_score'},
                    # FIX: Use pre-calculated date instead of timedelta in pipeline
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
        
        device_stats = list(verifications_collection.aggregate(pipeline))
        
        # Assign colors for consistency
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

        return jsonify({'deviceVerifications': device_verifications})

    except Exception as e:
        print(f"Error in manufacturer device analytics: {str(e)}")
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/manufacturer/verification-logs', methods=['GET'])
def get_manufacturer_verification_logs():
    """Get manufacturer's verification logs with enhanced device info"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        limit = int(request.args.get('limit', 50))
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)
        
        if not manufacturer_id:
            return jsonify({'error': 'manufacturerId is required'}), 400
        
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
                    # Determine device name from multiple sources
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
                    # Determine device category from multiple sources
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

        verifications = list(verifications_collection.aggregate(pipeline))

        verification_logs = []
        for verification in verifications:
            # Clean up device name if it's just spaces
            device_name = verification.get('final_device_name', 'Unknown Product').strip()
            if not device_name or device_name == ' ':
                device_name = 'Unknown Product'

            # Get customer info
            customer_data = verification.get('customer_data', {})
            customer_name = customer_data.get('name', 'Unknown Customer')
            customer_email = customer_data.get('email', 'Unknown Email')

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

        return jsonify({'verificationLogs': verification_logs})

    except Exception as e:
        print(f"Error getting manufacturer verification logs: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@analytics_bp.route('/analytics/manufacturer/detailed-device-breakdown', methods=['GET'])
def get_manufacturer_detailed_device_breakdown():
    """Get detailed device breakdown including specific models for manufacturer"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        device_category = request.args.get('deviceCategory')  # Filter by category if provided
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        match_criteria = {
            'manufacturer_id': ObjectId(manufacturer_id),
            'created_at': {'$gte': start_date}
        }
        
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
                    'device_info': {
                        '$switch': {
                            'branches': [
                                {
                                    'case': {'$ne': ['$device_name', None]},
                                    'then': {
                                        'name': '$device_name',
                                        'category': '$device_category'
                                    }
                                },
                                {
                                    'case': {'$ne': ['$product_data', None]},
                                    'then': {
                                        'name': {
                                            '$concat': [
                                                '$product_data.brand',
                                                ' ',
                                                '$product_data.model'
                                            ]
                                        },
                                        'category': '$product_data.device_type'
                                    }
                                },
                                {
                                    'case': {'$ne': ['$counterfeit_report_data.product_name', None]},
                                    'then': {
                                        'name': '$counterfeit_report_data.product_name',
                                        'category': '$counterfeit_report_data.device_category'
                                    }
                                }
                            ],
                            'default': {
                                'name': 'Unknown Product',
                                'category': 'Unknown'
                            }
                        }
                    }
                }
            }
        ]
        
        # Add category filter if specified
        if device_category:
            pipeline.append({
                '$match': {
                    'device_info.category': device_category
                }
            })
        
        pipeline.extend([
            {
                '$group': {
                    '_id': {
                        'name': '$device_info.name',
                        'category': '$device_info.category'
                    },
                    'verifications': {'$sum': 1},
                    'authentic': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    },
                    'unique_customers': {'$addToSet': '$customer_id'}
                }
            },
            {
                '$addFields': {
                    'customer_count': {'$size': '$unique_customers'}
                }
            },
            {'$sort': {'verifications': -1}}
        ])
        
        detailed_breakdown = list(verifications_collection.aggregate(pipeline))
        
        results = []
        for item in detailed_breakdown:
            results.append({
                'deviceName': item['_id']['name'],
                'deviceCategory': item['_id']['category'],
                'verifications': item['verifications'],
                'authentic': item['authentic'],
                'counterfeit': item['counterfeit'],
                'customerCount': item['customer_count']
            })
        
        return jsonify({'detailedBreakdown': results})
        
    except Exception as e:
        print(f"Error in detailed device breakdown: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@analytics_bp.route('/analytics/manufacturer/customer-engagement', methods=['GET'])
def get_manufacturer_customer_engagement():
    """Get customer engagement analytics for manufacturer"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': ObjectId(manufacturer_id),
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
                    'unique_customers': {'$addToSet': '$customer_id'},
                    'total_verifications': {'$sum': 1},
                    'avg_satisfaction': {'$avg': '$customer_satisfaction_rating'}
                }
            },
            {
                '$project': {
                    'date': '$_id',
                    'active_customers': {'$size': '$unique_customers'},
                    'total_verifications': 1,
                    'avg_satisfaction': {'$ifNull': ['$avg_satisfaction', 0]}
                }
            },
            {'$sort': {'date': 1}}
        ]
        
        engagement_stats = list(verifications_collection.aggregate(pipeline))
        
        customer_engagement = []
        for stat in engagement_stats:
            customer_engagement.append({
                'date': stat['date'],
                'activeCustomers': stat['active_customers'],
                'totalVerifications': stat['total_verifications'],
                'avgSatisfaction': round(stat['avg_satisfaction'], 1)
            })

        return jsonify({'customerEngagement': customer_engagement})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/manufacturer/counterfeit-locations', methods=['GET'])
def get_manufacturer_counterfeit_locations():
    """Get counterfeit detection locations for manufacturer"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': ObjectId(manufacturer_id),
                    'created_at': {'$gte': start_date},
                    'customer_consent': True
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
            {'$unwind': '$product'},
            {
                '$group': {
                    '_id': {
                        'city': '$city',
                        'state': '$state',
                        'device_type': '$product.device_type'
                    },
                    'report_count': {'$sum': 1}
                }
            },
            {'$sort': {'report_count': -1}}
        ]
        
        location_stats = list(counterfeit_reports_collection.aggregate(pipeline))
        
        counterfeit_locations = []
        for stat in location_stats:
            if stat['_id']['city'] and stat['_id']['state']:
                counterfeit_locations.append({
                    'location': f"{stat['_id']['city']}, {stat['_id']['state']}",
                    'deviceType': stat['_id']['device_type'],
                    'reports': stat['report_count']
                })

        return jsonify({'counterfeitLocations': counterfeit_locations})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# CUSTOMER ANALYTICS ROUTES

@analytics_bp.route('/analytics/customer/<customer_id>/overview', methods=['GET'])
def get_customer_overview(customer_id):
    """Get customer's personal analytics overview"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
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
        
        verification_history = list(verifications_collection.aggregate(history_pipeline))
        
        customer_history = []
        for history in verification_history:
            customer_history.append({
                'date': history['_id'],
                'verifications': history['verifications'],
                'authentic': history['authentic'],
                'counterfeit': history['counterfeit'],
                'avgTime': round(history['avg_time'] or 0, 2)
            })

        return jsonify({'customerHistory': customer_history})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/analytics/customer/<customer_id>/device-breakdown', methods=['GET'])
def get_customer_device_breakdown(customer_id):
    """Enhanced customer device breakdown with better data structure"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        # Simplified and more efficient pipeline
        device_pipeline = [
            {
                '$match': {
                    'customer_id': ObjectId(customer_id),
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
                '$addFields': {
                    'counterfeit_report_data': {'$arrayElemAt': ['$counterfeit_report', 0]},
                    'product_data': {'$arrayElemAt': ['$product', 0]},
                    # Determine final device info with priority order
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
                                            {'$ifNull': ['$product_data.brand', 'Unknown']},
                                            ' ',
                                            {'$ifNull': ['$product_data.model', 'Product']}
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
                            'default': 'Unknown'
                        }
                    }
                }
            },
            # Group by device category
            {
                '$group': {
                    '_id': '$final_device_category',
                    'total_count': {'$sum': 1},
                    'authentic_count': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit_count': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    },
                    # Also collect individual device names within each category
                    'device_names': {'$addToSet': '$final_device_name'}
                }
            },
            {'$sort': {'total_count': -1}}
        ]
        
        device_breakdown = list(verifications_collection.aggregate(device_pipeline))
        
        # Assign colors to different device types
        colors = ['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6', '#EC4899', '#6B7280']
        
        device_data = []
        for i, category in enumerate(device_breakdown):
            category_name = category['_id'] if category['_id'] and category['_id'] != 'Unknown' else 'Unknown Device'
            device_data.append({
                'name': category_name,
                'count': category['total_count'],
                'authentic': category['authentic_count'],
                'counterfeit': category['counterfeit_count'],
                'color': colors[i % len(colors)],
                'deviceNames': list(category['device_names'])  # For detailed breakdown if needed
            })
        
        return jsonify({'deviceBreakdown': device_data})
        
    except Exception as e:
        print(f"Error in customer device breakdown: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Simplified version if you want to group by category only
@analytics_bp.route('/analytics/customer/<customer_id>/device-categories', methods=['GET'])
def get_customer_device_categories(customer_id):
    """Get device categories from counterfeit products"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        category_pipeline = [
            {
                '$match': {
                    'customer_id': ObjectId(customer_id),
                    'created_at': {'$gte': start_date}
                }
            },
            {
                '$lookup': {
                    'from': 'counterfeit_reports',
                    'localField': '_id',
                    'foreignField': 'verification_id',
                    'as': 'report'
                }
            },
            {
                '$lookup': {
                    'from': 'counterfeit_products',
                    'let': {'verification_id': '$_id'},
                    'pipeline': [
                        {
                            '$match': {
                                '$expr': {
                                    '$or': [
                                        {'$eq': ['$verification_id', '$$verification_id']},
                                        {'$in': ['$counterfeit_report_id', '$report._id']},
                                        {'$in': ['$report_id', '$report._id']}
                                    ]
                                }
                            }
                        }
                    ],
                    'as': 'products'
                }
            },
            {
                '$addFields': {
                    'device_category': {
                        '$ifNull': [
                            {'$arrayElemAt': ['$products.device_category', 0]},
                            {'$arrayElemAt': ['$products.category', 0]},
                            'Unknown'
                        ]
                    }
                }
            },
            {
                '$group': {
                    '_id': '$device_category',
                    'count': {'$sum': 1},
                    'authentic': {'$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}},
                    'counterfeit': {'$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}}
                }
            }
        ]
        
        results = list(verifications_collection.aggregate(category_pipeline))
        
        device_data = []
        for item in results:
            device_data.append({
                'name': item['_id'] or 'Unknown',
                'count': item['count'],
                'authentic': item['authentic'],
                'counterfeit': item['counterfeit']
            })
        
        return jsonify({'deviceBreakdown': device_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@analytics_bp.route('/analytics/customer/<customer_id>/verification-logs', methods=['GET'])
def get_customer_verification_logs(customer_id):
    """Get customer's recent verification logs with enhanced device info and counterfeit linking"""
    try:
        limit = int(request.args.get('limit', 20))
        
        # Enhanced pipeline to get better device info and link counterfeit reports
        pipeline = [
            {
                '$match': {
                    'customer_id': ObjectId(customer_id)
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
                '$addFields': {
                    'counterfeit_report_data': {'$arrayElemAt': ['$counterfeit_report', 0]},
                    'product_data': {'$arrayElemAt': ['$product', 0]}
                }
            },
            {
                '$addFields': {
                    # Determine device name from multiple sources
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
                    # Determine device category from multiple sources
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

        verifications = list(verifications_collection.aggregate(pipeline))

        verification_logs = []
        for verification in verifications:
            # Clean up device name if it's just spaces
            device_name = verification.get('final_device_name', 'Unknown Product').strip()
            if not device_name or device_name == ' ':
                device_name = 'Unknown Product'

            log_entry = {
                'serialNumber': verification['serial_number'],
                'deviceName': device_name,
                'deviceCategory': verification.get('final_device_category', 'Unknown Category'),
                'status': 'Authentic' if verification['is_authentic'] else 'Counterfeit',
                'date': verification['created_at'].strftime('%Y-%m-%d'),
                'time': f"{verification.get('response_time', 0):.2f}s",
                'confidence': round(verification.get('confidence_score', 0), 1),
                'verificationMethod': verification.get('verification_method', 'manual'),
                'customerId': str(verification['customer_id'])
            }
            
            # Add counterfeit ID if this verification has a counterfeit report
            if verification.get('counterfeit_report_data'):
                log_entry['counterfeitId'] = str(verification['counterfeit_report_data']['_id'])
            
            verification_logs.append(log_entry)

        return jsonify({'verificationLogs': verification_logs})

    except Exception as e:
        print(f"Error getting verification logs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/analytics/customer/<customer_id>/counterfeit-reports', methods=['GET'])
def get_customer_counterfeit_reports(customer_id):
    """Get customer's counterfeit reports with verification linking"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date, _ = get_date_range(time_range)  # FIX: Unpack tuple properly
        
        pipeline = [
            {
                '$match': {
                    'customer_id': ObjectId(customer_id),
                    'created_at': {'$gte': start_date}
                }
            },
            {
                '$lookup': {
                    'from': 'verifications',
                    'localField': 'verification_id',
                    'foreignField': '_id',
                    'as': 'verification'
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
                '$addFields': {
                    'verification_data': {'$arrayElemAt': ['$verification', 0]},
                    'product_data': {'$arrayElemAt': ['$product', 0]}
                }
            },
            {'$sort': {'created_at': -1}}
        ]
        
        reports = list(counterfeit_reports_collection.aggregate(pipeline))
        
        counterfeit_reports = []
        for report in reports:
            product = report.get('product_data', {})
            verification = report.get('verification_data', {})
            
            report_entry = {
                'reportId': str(report['_id']),
                'serialNumber': report['serial_number'],
                'productName': report.get('product_name') or f"{product.get('brand', 'Unknown')} {product.get('model', 'Unknown')}", 
                'deviceCategory': report.get('device_category', 'Unknown'),
                'location': f"{report.get('city', 'N/A')}, {report.get('state', 'N/A')}" if report.get('city') else 'Not specified',
                'storeName': report.get('store_name', 'Not specified'),
                'storeAddress': report.get('store_address', 'Not specified'),
                'purchaseDate': report.get('purchase_date', '').strftime('%Y-%m-%d') if report.get('purchase_date') else 'Not specified',
                'purchasePrice': report.get('purchase_price', 0),
                'reportDate': report['created_at'].strftime('%Y-%m-%d'),
                'status': report.get('report_status', 'pending'),
                'additionalNotes': report.get('additional_notes', ''),
                'customerId': str(report['customer_id']),
                'verificationId': str(report.get('verification_id')) if report.get('verification_id') else None
            }
            
            counterfeit_reports.append(report_entry)

        return jsonify({'counterfeitReports': counterfeit_reports})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/analytics/record-verification', methods=['POST'])
def record_verification_attempt():
    """Enhanced record verification with device name and category"""
    try:
        data = request.get_json()
        
        serial_number = data.get('serialNumber')
        customer_id = data.get('customerId')
        is_authentic = data.get('isAuthentic', False)
        response_time = data.get('responseTime', 0)
        confidence_score = data.get('confidenceScore', 0)
        verification_method = data.get('verificationMethod', 'manual')
        
        # Enhanced device information
        device_name = data.get('deviceName', 'Unknown Product')
        device_category = data.get('deviceCategory', 'Unknown Category')
        brand = data.get('brand', 'Unknown Brand')
        
        # Find product if it exists
        product = None
        if is_authentic:
            product = products_collection.find_one({'serial_number': serial_number})
        
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
            
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = verifications_collection.insert_one(verification_doc)
        
        return jsonify({
            'success': True,
            'verificationId': str(result.inserted_id)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/counterfeit-reports', methods=['POST'])
def submit_counterfeit_report():
    """Enhanced counterfeit report submission with verification log update"""
    try:
        data = request.get_json()
        
        serial_number = data.get('serialNumber')
        product_name = data.get('productName')
        device_category = data.get('deviceCategory')
        customer_consent = data.get('customerConsent', False)
        location_data = data.get('locationData') if customer_consent else None
        customer_id_string = request.args.get('customerId')
        customer_id = ObjectId(customer_id_string)
        
        # Find the most recent verification for this customer and serial number
        verification = verifications_collection.find_one({
            'serial_number': serial_number,
            'customer_id': customer_id
        }, sort=[('created_at', -1)])  # Get the most recent one
        
        if not verification:
            return jsonify({'error': 'Verification not found'}), 404

        # **KEY ENHANCEMENT: Update the verification log with proper device info**
        try:
            # Update the verification document with the device information from counterfeit report
            verification_update = {
                'device_name': product_name,
                'device_category': device_category,
                'updated_at': datetime.utcnow()
            }
            
            # Extract brand from product name if possible
            if product_name:
                # Try to extract brand (first word usually)
                brand_guess = product_name.split()[0] if product_name.split() else 'Unknown'
                verification_update['brand'] = brand_guess
            
            # Update the verification record
            verifications_collection.update_one(
                {'_id': verification['_id']},
                {'$set': verification_update}
            )
            
            print(f"Updated verification log {verification['_id']} with device info: {product_name}, {device_category}")
            
        except Exception as update_error:
            print(f"Failed to update verification log: {str(update_error)}")
            # Don't fail the entire request if verification update fails

        # Create the counterfeit report as before
        report_doc = {
            'verification_id': verification['_id'],
            'product_id': verification.get('product_id'), 
            'manufacturer_id': verification.get('manufacturer_id'),  
            'customer_id': ObjectId(customer_id),
            'serial_number': serial_number,
            'product_name': product_name,  
            'device_category': device_category,
            'customer_consent': customer_consent,
            'report_status': 'pending',
            'created_at': datetime.utcnow()
        }
        
        if customer_consent and location_data:
            report_doc.update({
                'store_name': location_data.get('storeName'),
                'store_address': location_data.get('storeAddress'),
                'city': location_data.get('city'),
                'state': location_data.get('state'),
                'purchase_date': datetime.strptime(location_data.get('purchaseDate'), '%Y-%m-%d') if location_data.get('purchaseDate') else None,
                'purchase_price': float(location_data.get('purchasePrice', 0)) if location_data.get('purchasePrice') else None,
                'additional_notes': location_data.get('additionalNotes')
            })
        
        result = counterfeit_reports_collection.insert_one(report_doc)

        return jsonify({
            'success': True,
            'message': 'Counterfeit report submitted successfully and verification log updated',
            'reportId': str(result.inserted_id)
        })

    except Exception as e:
        print(f"Error submitting counterfeit report: {str(e)}")
        return jsonify({'error': str(e)}), 500 