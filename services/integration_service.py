"""
Manufacturer Integration Service

This service handles integration with manufacturer platforms, including:
- Account creation for manufacturers
- Customer log fetching (verification, counterfeit reports)
- API management for integrated systems
"""

from datetime import datetime, timezone, timedelta
from bson import ObjectId
import secrets
import hashlib
import jwt
import os
from typing import Dict, List, Optional, Any
from utils.helper_functions import (
    get_db_connection, get_user_by_id, create_user, hash_password,
    is_valid_email, email_exists_globally, get_current_utc,
    ValidationError, AuthenticationError
)

class ManufacturerIntegrationService:
    """Service for handling manufacturer platform integration"""
    
    def __init__(self):
        self.db = get_db_connection()
        self.secret_key = os.getenv('SECRET_KEY')
    
    def create_manufacturer_account(self, account_data: Dict) -> Dict[str, Any]:
        """
        Create a manufacturer account for integration purposes
        
        Args:
            account_data: Dictionary containing manufacturer details
            
        Returns:
            Dictionary with account creation results
        """
        try:
            # Validate required fields
            required_fields = ['company_name', 'contact_email', 'primary_wallet', 'integration_type']
            missing_fields = [field for field in required_fields if not account_data.get(field)]
            
            if missing_fields:
                raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # Validate email
            email = account_data['contact_email'].lower().strip()
            if not is_valid_email(email):
                raise ValidationError("Invalid email format")
            
            # Check if manufacturer already exists
            existing_manufacturer = self.db.users.find_one({
                "$or": [
                    {"primary_email": email},
                    {"current_company_name": account_data['company_name']},
                    {"primary_wallet": account_data['primary_wallet']}
                ],
                "role": "manufacturer"
            })
            
            if existing_manufacturer:
                raise ValidationError("Manufacturer with this email, company name, or wallet already exists")
            
            # Generate secure password for integration account
            temp_password = secrets.token_urlsafe(16)
            
            # Create manufacturer user data
            user_data = {
                "emails": [email],
                "primary_email": email,
                "password_hash": hash_password(temp_password),
                "role": "manufacturer",
                "wallet_addresses": [account_data['primary_wallet']],
                "primary_wallet": account_data['primary_wallet'],
                "company_names": [account_data['company_name']],
                "current_company_name": account_data['company_name'],
                "verification_status": "pending",
                "verified_wallets": [],
                "integration_enabled": True,
                "integration_type": account_data['integration_type'],
                "created_via": "integration",
                "created_at": get_current_utc(),
                "updated_at": get_current_utc()
            }
            
            # Add optional fields
            optional_fields = ['contact_person', 'phone_number', 'website', 'description']
            for field in optional_fields:
                if account_data.get(field):
                    user_data[field] = account_data[field]
            
            # Create user
            user_id = create_user(user_data)
            
            # Generate API keys for integration
            api_keys = self._generate_integration_api_keys(user_id, account_data['integration_type'])
            
            # Create integration profile
            integration_profile = {
                "manufacturer_id": user_id,
                "integration_type": account_data['integration_type'],
                "api_keys": api_keys,
                "webhook_url": account_data.get('webhook_url'),
                "allowed_origins": account_data.get('allowed_origins', []),
                "rate_limits": {
                    "requests_per_hour": account_data.get('rate_limit', 1000),
                    "burst_limit": account_data.get('burst_limit', 100)
                },
                "features_enabled": {
                    "product_verification": True,
                    "customer_analytics": True,
                    "counterfeit_reporting": True,
                    "ownership_tracking": True
                },
                "created_at": get_current_utc(),
                "updated_at": get_current_utc()
            }
            
            self.db.integration_profiles.insert_one(integration_profile)
            
            return {
                "status": "success",
                "manufacturer_id": str(user_id),
                "temporary_password": temp_password,
                "api_keys": api_keys,
                "message": "Manufacturer account created successfully. Please change password on first login."
            }
            
        except ValidationError as e:
            raise e
        except Exception as e:
            print(f"Error creating manufacturer account: {e}")
            raise Exception("Failed to create manufacturer account")
    
    def _generate_integration_api_keys(self, user_id: ObjectId, integration_type: str) -> Dict[str, str]:
        """Generate API keys for manufacturer integration"""
        
        # Generate different types of API keys based on integration type
        api_keys = {}
        
        # Main API key for general operations
        main_key = f"mk_{secrets.token_urlsafe(32)}"
        
        # Webhook key for secure webhook verification
        webhook_key = f"wh_{secrets.token_urlsafe(32)}"
        
        # Analytics read-only key
        analytics_key = f"an_{secrets.token_urlsafe(32)}"
        
        api_keys = {
            "main_api_key": main_key,
            "webhook_key": webhook_key,
            "analytics_key": analytics_key
        }
        
        # Store keys in database with metadata
        for key_type, key_value in api_keys.items():
            key_doc = {
                "user_id": user_id,
                "api_key": key_value,
                "key_type": key_type,
                "integration_type": integration_type,
                "permissions": self._get_key_permissions(key_type),
                "is_active": True,
                "created_at": get_current_utc(),
                "last_used": None,
                "usage_count": 0
            }
            self.db.api_keys.insert_one(key_doc)
        
        return api_keys
    
    def _get_key_permissions(self, key_type: str) -> List[str]:
        """Define permissions for different API key types"""
        permissions_map = {
            "main_api_key": [
                "product.register", "product.verify", "product.list",
                "analytics.read", "customer.logs.read"
            ],
            "webhook_key": [
                "webhook.receive", "events.process"
            ],
            "analytics_key": [
                "analytics.read", "customer.logs.read", "reports.read"
            ]
        }
        return permissions_map.get(key_type, [])
    
    def get_customer_logs(self, manufacturer_id: str, log_type: str = "all", 
                         limit: int = 100, offset: int = 0, 
                         date_from: Optional[datetime] = None,
                         date_to: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Fetch customer logs for a specific manufacturer
        
        Args:
            manufacturer_id: Manufacturer's user ID
            log_type: Type of logs to fetch ('verification', 'counterfeit', 'all')
            limit: Number of records to return
            offset: Number of records to skip
            date_from: Start date filter
            date_to: End date filter
            
        Returns:
            Dictionary containing logs and metadata
        """
        try:
            # Validate manufacturer
            manufacturer = get_user_by_id(manufacturer_id)
            if not manufacturer or manufacturer.get('role') != 'manufacturer':
                raise AuthenticationError("Invalid manufacturer ID")
            
            # Get manufacturer's products to filter logs
            manufacturer_wallet = manufacturer.get('primary_wallet')
            manufacturer_products = list(self.db.products.find(
                {"manufacturer_wallet": manufacturer_wallet},
                {"serial_number": 1, "_id": 0}
            ))
            
            if not manufacturer_products:
                return {
                    "status": "success",
                    "logs": [],
                    "total_count": 0,
                    "message": "No products found for this manufacturer"
                }
            
            serial_numbers = [product['serial_number'] for product in manufacturer_products]
            
            # Build query based on log type
            base_query = {"serial_number": {"$in": serial_numbers}}
            
            # Add date filters
            if date_from or date_to:
                date_filter = {}
                if date_from:
                    date_filter["$gte"] = date_from
                if date_to:
                    date_filter["$lte"] = date_to
                base_query["timestamp"] = date_filter
            
            logs = []
            total_count = 0
            
            # Fetch verification logs
            if log_type in ['verification', 'all']:
                verification_query = {**base_query}
                verification_logs = list(
                    self.db.verifications.find(verification_query)
                    .sort("timestamp", -1)
                    .skip(offset)
                    .limit(limit if log_type == 'verification' else limit // 2)
                )
                
                for log in verification_logs:
                    logs.append({
                        "log_type": "verification",
                        "serial_number": log.get("serial_number"),
                        "customer_id": str(log.get("customer_id")) if log.get("customer_id") else None,
                        "is_authentic": log.get("is_authentic"),
                        "verification_method": log.get("verification_method"),
                        "confidence_score": log.get("confidence_score"),
                        "device_info": {
                            "brand": log.get("brand"),
                            "model": log.get("device_name"),
                            "category": log.get("device_category")
                        },
                        "timestamp": log.get("timestamp"),
                        "user_ip": log.get("user_ip"),
                        "source": log.get("source")
                    })
                
                total_count += self.db.verifications.count_documents(verification_query)
            
            # Fetch counterfeit reports
            if log_type in ['counterfeit', 'all']:
                counterfeit_query = {**base_query}
                counterfeit_logs = list(
                    self.db.counterfeit_reports.find(counterfeit_query)
                    .sort("timestamp", -1)
                    .skip(offset)
                    .limit(limit if log_type == 'counterfeit' else limit // 2)
                )
                
                for log in counterfeit_logs:
                    logs.append({
                        "log_type": "counterfeit_report",
                        "serial_number": log.get("serial_number"),
                        "reporter_id": str(log.get("reporter_id")) if log.get("reporter_id") else None,
                        "report_reason": log.get("reason"),
                        "description": log.get("description"),
                        "evidence": log.get("evidence", []),
                        "status": log.get("status"),
                        "timestamp": log.get("timestamp"),
                        "user_ip": log.get("user_ip")
                    })
                
                total_count += self.db.counterfeit_reports.count_documents(counterfeit_query)
            
            # Sort combined logs by timestamp
            logs.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
            
            return {
                "status": "success",
                "logs": logs[:limit],
                "total_count": total_count,
                "returned_count": len(logs[:limit]),
                "log_type": log_type,
                "manufacturer_id": manufacturer_id
            }
            
        except Exception as e:
            print(f"Error fetching customer logs: {e}")
            raise Exception("Failed to fetch customer logs")
    
    def get_manufacturer_analytics(self, manufacturer_id: str, 
                                 time_period: str = "30d") -> Dict[str, Any]:
        """
        Get analytics data for a specific manufacturer
        
        Args:
            manufacturer_id: Manufacturer's user ID
            time_period: Time period for analytics ('7d', '30d', '90d', '1y')
            
        Returns:
            Dictionary containing analytics data
        """
        try:
            # Calculate date range
            period_map = {
                '7d': 7,
                '30d': 30,
                '90d': 90,
                '1y': 365
            }
            
            days = period_map.get(time_period, 30)
            date_from = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Get customer logs with date filter
            logs_data = self.get_customer_logs(
                manufacturer_id, 
                log_type="all", 
                limit=10000,  # Get all for analytics
                date_from=date_from
            )
            
            logs = logs_data.get('logs', [])
            
            # Calculate analytics metrics
            analytics = {
                "time_period": time_period,
                "date_range": {
                    "from": date_from.isoformat(),
                    "to": datetime.now(timezone.utc).isoformat()
                },
                "verification_stats": self._calculate_verification_stats(logs),
                "counterfeit_stats": self._calculate_counterfeit_stats(logs),
                "customer_engagement": self._calculate_customer_engagement(logs),
                "product_performance": self._calculate_product_performance(logs),
                "geographic_distribution": self._calculate_geographic_stats(logs),
                "trend_analysis": self._calculate_trends(logs, days)
            }
            
            return {
                "status": "success",
                "analytics": analytics,
                "manufacturer_id": manufacturer_id
            }
            
        except Exception as e:
            print(f"Error generating manufacturer analytics: {e}")
            raise Exception("Failed to generate analytics")
    
    def _calculate_verification_stats(self, logs: List[Dict]) -> Dict[str, Any]:
        """Calculate verification statistics"""
        verification_logs = [log for log in logs if log.get('log_type') == 'verification']
        
        total_verifications = len(verification_logs)
        authentic_verifications = len([log for log in verification_logs if log.get('is_authentic')])
        
        authenticity_rate = (authentic_verifications / total_verifications * 100) if total_verifications > 0 else 0
        
        return {
            "total_verifications": total_verifications,
            "authentic_verifications": authentic_verifications,
            "fake_detections": total_verifications - authentic_verifications,
            "authenticity_rate": round(authenticity_rate, 2)
        }
    
    def _calculate_counterfeit_stats(self, logs: List[Dict]) -> Dict[str, Any]:
        """Calculate counterfeit report statistics"""
        counterfeit_logs = [log for log in logs if log.get('log_type') == 'counterfeit_report']
        
        return {
            "total_reports": len(counterfeit_logs),
            "pending_reports": len([log for log in counterfeit_logs if log.get('status') == 'pending']),
            "resolved_reports": len([log for log in counterfeit_logs if log.get('status') == 'resolved']),
            "rejected_reports": len([log for log in counterfeit_logs if log.get('status') == 'rejected'])
        }
    
    def _calculate_customer_engagement(self, logs: List[Dict]) -> Dict[str, Any]:
        """Calculate customer engagement metrics"""
        unique_customers = set()
        for log in logs:
            customer_id = log.get('customer_id')
            if customer_id:
                unique_customers.add(customer_id)
        
        return {
            "unique_customers": len(unique_customers),
            "total_interactions": len(logs),
            "avg_interactions_per_customer": round(len(logs) / len(unique_customers), 2) if unique_customers else 0
        }
    
    def _calculate_product_performance(self, logs: List[Dict]) -> Dict[str, Any]:
        """Calculate product performance metrics"""
        product_stats = {}
        
        for log in logs:
            serial_number = log.get('serial_number')
            if serial_number:
                if serial_number not in product_stats:
                    product_stats[serial_number] = {
                        'verifications': 0,
                        'counterfeit_reports': 0,
                        'device_info': log.get('device_info', {})
                    }
                
                if log.get('log_type') == 'verification':
                    product_stats[serial_number]['verifications'] += 1
                elif log.get('log_type') == 'counterfeit_report':
                    product_stats[serial_number]['counterfeit_reports'] += 1
        
        # Get top performing products
        top_products = sorted(
            product_stats.items(), 
            key=lambda x: x[1]['verifications'], 
            reverse=True
        )[:10]
        
        return {
            "total_products_with_activity": len(product_stats),
            "top_verified_products": [
                {
                    "serial_number": serial,
                    "verifications": stats['verifications'],
                    "device_info": stats['device_info']
                }
                for serial, stats in top_products
            ]
        }
    
    def _calculate_geographic_stats(self, logs: List[Dict]) -> Dict[str, Any]:
        """Calculate geographic distribution (basic IP-based)"""
        # This is a simplified version - in production, you might use IP geolocation services
        ip_addresses = set()
        for log in logs:
            user_ip = log.get('user_ip')
            if user_ip:
                ip_addresses.add(user_ip)
        
        return {
            "unique_locations": len(ip_addresses),
            "note": "Geographic data requires IP geolocation service integration"
        }
    
    def _calculate_trends(self, logs: List[Dict], days: int) -> Dict[str, Any]:
        """Calculate trend analysis"""
        # Group logs by day
        daily_stats = {}
        
        for log in logs:
            timestamp = log.get('timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                date_key = timestamp.date().isoformat()
                
                if date_key not in daily_stats:
                    daily_stats[date_key] = {'verifications': 0, 'reports': 0}
                
                if log.get('log_type') == 'verification':
                    daily_stats[date_key]['verifications'] += 1
                elif log.get('log_type') == 'counterfeit_report':
                    daily_stats[date_key]['reports'] += 1
        
        # Calculate growth rates
        sorted_dates = sorted(daily_stats.keys())
        
        return {
            "daily_breakdown": daily_stats,
            "trend_period_days": days,
            "most_active_day": max(daily_stats.keys(), 
                                 key=lambda x: daily_stats[x]['verifications']) if daily_stats else None
        }
    
    def validate_api_key(self, api_key: str, required_permission: str = None) -> Optional[Dict[str, Any]]:
        """
        Validate API key and check permissions
        
        Args:
            api_key: The API key to validate
            required_permission: Required permission for the operation
            
        Returns:
            API key data if valid, None otherwise
        """
        try:
            key_data = self.db.api_keys.find_one({
                "api_key": api_key,
                "is_active": True
            })
            
            if not key_data:
                return None
            
            # Check permission if required
            if required_permission:
                permissions = key_data.get('permissions', [])
                if required_permission not in permissions:
                    return None
            
            # Update usage statistics
            self.db.api_keys.update_one(
                {"api_key": api_key},
                {
                    "$set": {"last_used": get_current_utc()},
                    "$inc": {"usage_count": 1}
                }
            )
            
            return key_data
            
        except Exception as e:
            print(f"Error validating API key: {e}")
            return None

# Global instance for easy import
manufacturer_integration = ManufacturerIntegrationService()