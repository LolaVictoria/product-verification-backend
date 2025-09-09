from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient
from collections import defaultdict
from helper_functions import get_db_connection

analytics_bp = Blueprint('analytics', __name__)
db = get_db_connection()

users_collection = db.users
products_collection = db.products
verifications_collection = db.verifications
counterfeit_reports_collection = db.counterfeit_reports

def get_date_range(time_range):
    """Helper function to calculate date range"""
    if time_range == '7d':
        return datetime.utcnow() - timedelta(days=7)
    elif time_range == '30d':
        return datetime.utcnow() - timedelta(days=30)
    elif time_range == '90d':
        return datetime.utcnow() - timedelta(days=90)
    elif time_range == '1y':
        return datetime.utcnow() - timedelta(days=365)
    else:
        return datetime.utcnow() - timedelta(days=7)

# MANUFACTURER ANALYTICS ROUTES

@analytics_bp.route('/analytics/manufacturer/overview', methods=['GET'])
def get_manufacturer_overview():
    """Get manufacturer analytics overview with KPIs"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date = get_date_range(time_range)
        
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
        start_date = get_date_range(time_range)
        
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
    """Get verification analytics by device type for manufacturer"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date = get_date_range(time_range)
        
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
            {'$unwind': '$product'},
            {
                '$group': {
                    '_id': '$product.device_type',
                    'total_verifications': {'$sum': 1},
                    'authentic': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    }
                }
            }
        ]
        
        device_stats = list(verifications_collection.aggregate(pipeline))
        
        device_verifications = []
        for stat in device_stats:
            device_verifications.append({
                'name': stat['_id'],
                'verifications': stat['total_verifications'],
                'authentic': stat['authentic'],
                'counterfeit': stat['counterfeit']
            })

        return jsonify({'deviceVerifications': device_verifications})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/manufacturer/customer-engagement', methods=['GET'])
def get_manufacturer_customer_engagement():
    """Get customer engagement analytics for manufacturer"""
    try:
        manufacturer_id = request.args.get('manufacturerId')
        time_range = request.args.get('timeRange', '30d')
        start_date = get_date_range(time_range)
        
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
        start_date = get_date_range(time_range)
        
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
        start_date = get_date_range(time_range)
        
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
    """Get customer's device verification breakdown"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date = get_date_range(time_range)
        
        device_pipeline = [
            {
                '$match': {
                    'customer_id': ObjectId(customer_id),
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
            {'$unwind': '$product'},
            {
                '$group': {
                    '_id': '$product.device_type',
                    'count': {'$sum': 1},
                    'authentic': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}
                    },
                    'counterfeit': {
                        '$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}
                    }
                }
            }
        ]
        
        device_breakdown = list(verifications_collection.aggregate(device_pipeline))
        
        device_data = []
        for device in device_breakdown:
            device_data.append({
                'name': device['_id'],
                'count': device['count'],
                'authentic': device['authentic'],
                'counterfeit': device['counterfeit']
            })

        return jsonify({'deviceBreakdown': device_data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/customer/<customer_id>/verification-logs', methods=['GET'])
def get_customer_verification_logs(customer_id):
    """Get customer's recent verification logs"""
    try:
        limit = int(request.args.get('limit', 20))
        
        verifications = list(verifications_collection.find({
            'customer_id': ObjectId(customer_id)
        }).sort('created_at', -1).limit(limit))

        verification_logs = []
        for verification in verifications:
            product_name = "Unknown Product"
            device_category = "Unknown"  
            
            # Try to find related counterfeit report for product info
            related_report = counterfeit_reports_collection.find_one({
                'verification_id': verification['_id']
            })
            
            if related_report:
                if related_report.get('product_name'):
                    product_name = related_report.get('product_name')
                if related_report.get('device_category'):
                    device_category = related_report.get('device_category')
            
            verification_logs.append({
                'serialNumber': verification['serial_number'],
                'product': product_name,
                'deviceCategory': device_category,
                'status': 'Authentic' if verification['is_authentic'] else 'Counterfeit',
                'date': verification['created_at'].strftime('%Y-%m-%d'),
                'time': f"{verification.get('response_time', 0):.2f}s",
                'confidence': round(verification.get('confidence_score', 0), 1),
                'verificationMethod': verification.get('verification_method', 'manual')
            })

        return jsonify({'verificationLogs': verification_logs})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/customer/<customer_id>/counterfeit-reports', methods=['GET'])
def get_customer_counterfeit_reports(customer_id):
    """Get customer's counterfeit reports with location details"""
    try:
        time_range = request.args.get('timeRange', '30d')
        start_date = get_date_range(time_range)
        
        reports = list(counterfeit_reports_collection.aggregate([
            {
                '$match': {
                    'customer_id': ObjectId(customer_id),
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
            {'$unwind': {'path': '$product', 'preserveNullAndEmptyArrays': True}},
            {'$sort': {'created_at': -1}}
        ]))
        
        counterfeit_reports = []
        for report in reports:
            product = report.get('product', {})
            counterfeit_reports.append({
                'reportId': str(report['_id']),
                'serialNumber': report['serial_number'],
                'productName': f"{product.get('brand', 'Unknown')} {product.get('model', 'Unknown')}", 
                'deviceCategory': report.get('device_category', 'Unknown'),
                'location': f"{report.get('city', 'N/A')}, {report.get('state', 'N/A')}" if report.get('city') else 'Not specified',
                'storeName': report.get('store_name', 'Not specified'),
                'storeAddress': report.get('store_address', 'Not specified'),
                'purchaseDate': report.get('purchase_date', '').strftime('%Y-%m-%d') if report.get('purchase_date') else 'Not specified',
                'purchasePrice': report.get('purchase_price', 0),
                'reportDate': report['created_at'].strftime('%Y-%m-%d'),
                'status': report.get('report_status', 'pending'),
                'additionalNotes': report.get('additional_notes', '')
            })

        return jsonify({'counterfeitReports': counterfeit_reports})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# SHARED ROUTES
@analytics_bp.route('/counterfeit-reports', methods=['POST'])
def submit_counterfeit_report():
    """Submit counterfeit report with optional location data"""
    try:
        data = request.get_json()
        
        serial_number = data.get('serialNumber')
        product_name = data.get('productName')
        device_category = data.get('deviceCategory')
        customer_consent = data.get('customerConsent', False)
        location_data = data.get('locationData') if customer_consent else None
        customer_id_string = request.args.get('customerId')  # "68ab7eb7a12da4179ca1fc00"
        customer_id = ObjectId(customer_id_string)
        # Find the verification
        verification = verifications_collection.find_one({
            'serial_number': serial_number,
            'customer_id': customer_id
        })
        
        if not verification:
            return jsonify({'error': 'Verification not found'}), 404

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
            'message': 'Counterfeit report submitted successfully',
            'reportId': str(result.inserted_id)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/record-verification', methods=['POST'])
def record_verification_attempt():
    """Record a verification attempt for analytics tracking"""
    try:
        data = request.get_json()
        
        serial_number = data.get('serialNumber')
        customer_id = data.get('customerId')
        is_authentic = data.get('isAuthentic', False)
        response_time = data.get('responseTime', 0)
        confidence_score = data.get('confidenceScore', 0)
        verification_method = data.get('verificationMethod', 'manual')
        
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