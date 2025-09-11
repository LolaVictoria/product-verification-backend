from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, List, Optional, Tuple
import secrets
import hashlib
from utils.crypto_utils import generate_api_key, hash_api_key
from utils.validators import validate_manufacturer_data
from config.__init__ import DatabaseConfig

class ManufacturerService:

    """Service for manufacturer account management and integration"""
    
    def __init__(self):
        self.db = DatabaseConfig.get_db_connection()
    
    def create_manufacturer_account(self, account_data: Dict) -> Dict:
        """
        Create a new manufacturer account with integration capabilities
        
        Args:
            account_data: Dictionary containing manufacturer registration data
            
        Returns:
            Dictionary with account creation result and integration credentials
        """
        try:
            # Validate input data
            validation_result = validate_manufacturer_data(account_data)
            if not validation_result['valid']:
                raise ValueError(validation_result['errors'])
            
            # Check for existing manufacturer
            existing = self.db.users.find_one({
                "$or": [
                    {"primary_email": account_data['email']},
                    {"company_names": account_data['company_name']}
                ]
            })
            
            if existing:
                raise ValueError("Manufacturer with this email or company name already exists")
            
            # Create manufacturer account
            manufacturer_data = {
                "_id": ObjectId(),
                "emails": [account_data['email']],
                "primary_email": account_data['email'],
                "password_hash": self._hash_password(account_data['password']),
                "role": "manufacturer",
                "company_names": [account_data['company_name']],
                "current_company_name": account_data['company_name'],
                "wallet_addresses": [account_data['wallet_address']],
                "primary_wallet": account_data['wallet_address'],
                "verification_status": "pending",
                "verified_wallets": [],
                "integration_enabled": True,
                "integration_settings": {
                    "webhook_url": account_data.get('webhook_url'),
                    "allowed_origins": account_data.get('allowed_origins', []),
                    "rate_limit": account_data.get('rate_limit', 1000),  # requests per hour
                    "data_retention_days": account_data.get('data_retention_days', 90)
                },
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            # Insert manufacturer
            result = self.db.users.insert_one(manufacturer_data)
            manufacturer_id = result.inserted_id
            
            # Generate API credentials
            api_credentials = self._generate_api_credentials(manufacturer_id)
            
            # Create integration profile
            integration_profile = self._create_integration_profile(
                manufacturer_id, 
                account_data['company_name'],
                api_credentials
            )
            
            return {
                "success": True,
                "manufacturer_id": str(manufacturer_id),
                "company_name": account_data['company_name'],
                "api_credentials": api_credentials,
                "integration_profile": integration_profile,
                "message": "Manufacturer account created successfully. Pending admin verification."
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_api_credentials(self, manufacturer_id: ObjectId) -> Dict:
        """Generate API keys and integration credentials"""
        
        # Generate primary API key
        api_key = generate_api_key()
        api_key_hash = hash_api_key(api_key)
        
        # Generate webhook secret
        webhook_secret = secrets.token_urlsafe(32)
        
        # Store API key
        api_key_doc = {
            "_id": ObjectId(),
            "user_id": manufacturer_id,
            "api_key_hash": api_key_hash,
            "key_type": "integration",
            "permissions": [
                "read:products",
                "write:products",
                "read:verifications",
                "read:analytics",
                "webhook:receive"
            ],
            "webhook_secret": webhook_secret,
            "rate_limit": 1000,  # requests per hour
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "expires_at": None  # No expiration for integration keys
        }
        
        self.db.api_keys.insert_one(api_key_doc)
        
        return {
            "api_key": api_key,  # Only return this once
            "api_key_id": str(api_key_doc["_id"]),
            "webhook_secret": webhook_secret,
            "permissions": api_key_doc["permissions"]
        }
    
    def _create_integration_profile(self, manufacturer_id: ObjectId, company_name: str, api_credentials: Dict) -> Dict:
        """Create integration profile with configuration"""
        
        integration_doc = {
            "_id": ObjectId(),
            "manufacturer_id": manufacturer_id,
            "company_name": company_name,
            "api_key_id": ObjectId(api_credentials["api_key_id"]),
            "integration_type": "direct_api",
            "status": "active",
            "configuration": {
                "data_sync_enabled": True,
                "real_time_notifications": True,
                "analytics_access": "full",
                "verification_logs_access": True,
                "counterfeit_reports_access": True
            },
            "usage_metrics": {
                "total_requests": 0,
                "last_request": None,
                "monthly_usage": 0
            },
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        result = self.db.integrations.insert_one(integration_doc)
        
        return {
            "integration_id": str(result.inserted_id),
            "status": "active",
            "configuration": integration_doc["configuration"]
        }
    
    def get_manufacturer_integration_data(self, manufacturer_id: str, time_range: str = '30d') -> Dict:
        """
        Get comprehensive integration data for manufacturer's platform
        
        Args:
            manufacturer_id: Manufacturer's ID
            time_range: Time range for analytics (7d, 30d, 90d, 1y)
            
        Returns:
            Complete integration data package
        """
        try:
            manufacturer_obj_id = ObjectId(manufacturer_id)
            
            # Get manufacturer info
            manufacturer = self.db.users.find_one({"_id": manufacturer_obj_id})
            if not manufacturer:
                raise ValueError("Manufacturer not found")
            
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            days_map = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
            days = days_map.get(time_range, 30)
            start_date = end_date - timedelta(days=days)
            
            # Get products
            products = list(self.db.products.find({
                "manufacturer_id": manufacturer_obj_id
            }).sort("created_at", -1))
            
            # Get verification logs
            verification_logs = self._get_verification_logs(manufacturer_obj_id, start_date, end_date)
            
            # Get counterfeit reports
            counterfeit_reports = self._get_counterfeit_reports(manufacturer_obj_id, start_date, end_date)
            
            # Get analytics summary
            analytics = self._get_analytics_summary(manufacturer_obj_id, start_date, end_date)
            
            # Get integration metrics
            integration_metrics = self._get_integration_metrics(manufacturer_obj_id)
            
            return {
                "manufacturer_info": {
                    "id": str(manufacturer["_id"]),
                    "company_name": manufacturer.get("current_company_name"),
                    "verification_status": manufacturer.get("verification_status"),
                    "primary_wallet": manufacturer.get("primary_wallet"),
                    "created_at": manufacturer.get("created_at")
                },
                "products": self._format_products_for_integration(products),
                "verification_logs": verification_logs,
                "counterfeit_reports": counterfeit_reports,
                "analytics": analytics,
                "integration_metrics": integration_metrics,
                "time_range": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "period": time_range
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_verification_logs(self, manufacturer_id: ObjectId, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get detailed verification logs for manufacturer"""
        
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': manufacturer_id,
                    'created_at': {'$gte': start_date, '$lte': end_date}
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
                '$lookup': {
                    'from': 'products',
                    'localField': 'product_id',
                    'foreignField': '_id',
                    'as': 'product'
                }
            },
            {
                '$addFields': {
                    'customer_data': {'$arrayElemAt': ['$customer', 0]},
                    'product_data': {'$arrayElemAt': ['$product', 0]}
                }
            },
            {'$sort': {'created_at': -1}},
            {'$limit': 500}  # Limit for performance
        ]
        
        verifications = list(self.db.verifications.aggregate(pipeline))
        
        formatted_logs = []
        for verification in verifications:
            customer_data = verification.get('customer_data', {})
            product_data = verification.get('product_data', {})
            
            log_entry = {
                'verification_id': str(verification['_id']),
                'serial_number': verification.get('serial_number'),
                'device_name': verification.get('device_name') or f"{product_data.get('brand', '')} {product_data.get('model', '')}".strip(),
                'device_category': verification.get('device_category') or product_data.get('device_type'),
                'is_authentic': verification.get('is_authentic'),
                'confidence_score': verification.get('confidence_score'),
                'response_time': verification.get('response_time'),
                'verification_method': verification.get('verification_method'),
                'customer_info': {
                    'customer_id': str(verification.get('customer_id')) if verification.get('customer_id') else None,
                    'email': customer_data.get('primary_email') if customer_data else None
                },
                'timestamp': verification.get('created_at').isoformat(),
                'user_ip': verification.get('user_ip'),
                'user_agent': verification.get('user_agent')
            }
            
            formatted_logs.append(log_entry)
        
        return formatted_logs
    
    def _get_counterfeit_reports(self, manufacturer_id: ObjectId, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get counterfeit reports for manufacturer"""
        
        pipeline = [
            {
                '$match': {
                    'manufacturer_id': manufacturer_id,
                    'created_at': {'$gte': start_date, '$lte': end_date}
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
                '$lookup': {
                    'from': 'verifications',
                    'localField': 'verification_id',
                    'foreignField': '_id',
                    'as': 'verification'
                }
            },
            {
                '$addFields': {
                    'customer_data': {'$arrayElemAt': ['$customer', 0]},
                    'verification_data': {'$arrayElemAt': ['$verification', 0]}
                }
            },
            {'$sort': {'created_at': -1}}
        ]
        
        reports = list(self.db.counterfeit_reports.aggregate(pipeline))
        
        formatted_reports = []
        for report in reports:
            customer_data = report.get('customer_data', {})
            
            report_entry = {
                'report_id': str(report['_id']),
                'verification_id': str(report.get('verification_id')) if report.get('verification_id') else None,
                'serial_number': report.get('serial_number'),
                'product_name': report.get('product_name'),
                'device_category': report.get('device_category'),
                'customer_info': {
                    'customer_id': str(report.get('customer_id')) if report.get('customer_id') else None,
                    'email': customer_data.get('primary_email') if customer_data else None
                },
                'location_data': {
                    'store_name': report.get('store_name'),
                    'store_address': report.get('store_address'),
                    'city': report.get('city'),
                    'state': report.get('state')
                } if report.get('customer_consent') else None,
                'purchase_info': {
                    'purchase_date': report.get('purchase_date').isoformat() if report.get('purchase_date') else None,
                    'purchase_price': report.get('purchase_price')
                } if report.get('customer_consent') else None,
                'report_status': report.get('report_status', 'pending'),
                'additional_notes': report.get('additional_notes'),
                'timestamp': report.get('created_at').isoformat()
            }
            
            formatted_reports.append(report_entry)
        
        return formatted_reports
    
    def _get_analytics_summary(self, manufacturer_id: ObjectId, start_date: datetime, end_date: datetime) -> Dict:
        """Get analytics summary for manufacturer"""
        
        # Total products
        total_products = self.db.products.count_documents({"manufacturer_id": manufacturer_id})
        
        # Verification statistics
        verification_stats = list(self.db.verifications.aggregate([
            {
                '$match': {
                    'manufacturer_id': manufacturer_id,
                    'created_at': {'$gte': start_date, '$lte': end_date}
                }
            },
            {
                '$group': {
                    '_id': None,
                    'total_verifications': {'$sum': 1},
                    'authentic_count': {'$sum': {'$cond': [{'$eq': ['$is_authentic', True]}, 1, 0]}},
                    'counterfeit_count': {'$sum': {'$cond': [{'$eq': ['$is_authentic', False]}, 1, 0]}},
                    'avg_response_time': {'$avg': '$response_time'},
                    'avg_confidence': {'$avg': '$confidence_score'}
                }
            }
        ]))
        
        stats = verification_stats[0] if verification_stats else {
            'total_verifications': 0,
            'authentic_count': 0,
            'counterfeit_count': 0,
            'avg_response_time': 0,
            'avg_confidence': 0
        }
        
        # Counterfeit reports count
        counterfeit_reports_count = self.db.counterfeit_reports.count_documents({
            'manufacturer_id': manufacturer_id,
            'created_at': {'$gte': start_date, '$lte': end_date}
        })
        
        return {
            'total_products': total_products,
            'verification_metrics': {
                'total_verifications': stats['total_verifications'],
                'authentic_verifications': stats['authentic_count'],
                'counterfeit_detections': stats['counterfeit_count'],
                'authenticity_rate': round((stats['authentic_count'] / max(stats['total_verifications'], 1)) * 100, 2),
                'avg_response_time': round(stats['avg_response_time'] or 0, 2),
                'avg_confidence_score': round(stats['avg_confidence'] or 0, 1)
            },
            'counterfeit_reports_count': counterfeit_reports_count
        }
    
    def _get_integration_metrics(self, manufacturer_id: ObjectId) -> Dict:
        """Get integration usage metrics"""
        
        integration = self.db.integrations.find_one({"manufacturer_id": manufacturer_id})
        
        if not integration:
            return {
                'status': 'not_configured',
                'usage_metrics': {
                    'total_requests': 0,
                    'last_request': None,
                    'monthly_usage': 0
                }
            }
        
        return {
            'integration_id': str(integration['_id']),
            'status': integration.get('status', 'inactive'),
            'configuration': integration.get('configuration', {}),
            'usage_metrics': integration.get('usage_metrics', {})
        }
    
    def _format_products_for_integration(self, products: List[Dict]) -> List[Dict]:
        """Format products for integration response"""
        
        formatted_products = []
        for product in products:
            formatted_product = {
                'product_id': str(product['_id']),
                'serial_number': product.get('serial_number'),
                'name': product.get('name') or f"{product.get('brand', '')} {product.get('model', '')}".strip(),
                'brand': product.get('brand'),
                'model': product.get('model'),
                'device_type': product.get('device_type'),
                'registration_type': product.get('registration_type'),
                'blockchain_verified': product.get('blockchain_verified', False),
                'transaction_hash': product.get('transaction_hash'),
                'created_at': product.get('created_at').isoformat() if product.get('created_at') else None,
                'updated_at': product.get('updated_at').isoformat() if product.get('updated_at') else None
            }
            
            formatted_products.append(formatted_product)
        
        return formatted_products
    
    def _hash_password(self, password: str) -> str:
        """Hash password using secure method"""
        import bcrypt
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def update_integration_usage(self, manufacturer_id: str, request_count: int = 1):
        """Update integration usage metrics"""
        try:
            self.db.integrations.update_one(
                {"manufacturer_id": ObjectId(manufacturer_id)},
                {
                    "$inc": {
                        "usage_metrics.total_requests": request_count,
                        "usage_metrics.monthly_usage": request_count
                    },
                    "$set": {
                        "usage_metrics.last_request": datetime.now(timezone.utc)
                    }
                }
            )
        except Exception as e:
            print(f"Failed to update integration usage: {e}")

manufacturer_service = ManufacturerService()