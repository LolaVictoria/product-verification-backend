"""
Subscription Service
Business logic for subscription management, plan limits, and usage tracking
"""

import logging
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, Any, Optional, List

from app.config.database import get_db_connection
from app.services.billing.stripe_service import stripe_service

logger = logging.getLogger(__name__)


class SubscriptionService:
    """Handles subscription lifecycle and business logic"""
    
    def __init__(self):
        self.db = get_db_connection()
        
        # Plan definitions
        self.plans = {
            'free': {
                'name': 'Free Trial',
                'price_monthly': 0,
                'price_yearly': 0,
                'limits': {
                    'api_requests_per_month': 1000,
                    'products': 100,
                    'api_keys': 1,
                    'team_members': 1,
                    'analytics_retention_days': 30
                },
                'features': ['basic_verification', 'email_support']
            },
            'starter': {
                'name': 'Starter',
                'price_monthly': 99,
                'price_yearly': 950,
                'limits': {
                    'api_requests_per_month': 10000,
                    'products': 1000,
                    'api_keys': 3,
                    'team_members': 3,
                    'analytics_retention_days': 90
                },
                'features': ['basic_verification', 'blockchain_verification', 
                            'email_support', 'basic_analytics']
            },
            'professional': {
                'name': 'Professional',
                'price_monthly': 299,
                'price_yearly': 2990,
                'limits': {
                    'api_requests_per_month': 100000,
                    'products': 10000,
                    'api_keys': 10,
                    'team_members': 10,
                    'analytics_retention_days': 365
                },
                'features': ['basic_verification', 'blockchain_verification',
                            'priority_support', 'advanced_analytics', 'custom_webhooks']
            },
            'enterprise': {
                'name': 'Enterprise',
                'price_monthly': 999,
                'price_yearly': 9990,
                'limits': {
                    'api_requests_per_month': -1,  # Unlimited
                    'products': -1,
                    'api_keys': -1,
                    'team_members': -1,
                    'analytics_retention_days': -1
                },
                'features': ['basic_verification', 'blockchain_verification',
                            'priority_support', 'advanced_analytics', 'custom_webhooks',
                            'dedicated_account_manager', 'custom_integration']
            }
        }
    
    def get_subscription_status(self, manufacturer_id: str) -> Dict[str, Any]:
        """
        Get current subscription status for manufacturer
        
        Args:
            manufacturer_id: Manufacturer ID
            
        Returns:
            Dict with subscription details
        """
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            subscription = self.db.subscriptions.find_one({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            if not subscription:
                # Return free plan as default
                return {
                    'success': True,
                    'subscription': {
                        'plan': 'free',
                        'status': 'active',
                        'limits': self.plans['free']['limits'],
                        'features': self.plans['free']['features']
                    }
                }
            
            # Check if we need to sync with Stripe
            if subscription.get('stripe_subscription_id'):
                stripe_sub = stripe_service.retrieve_stripe_subscription(
                    subscription['stripe_subscription_id']
                )
                
                if stripe_sub and stripe_sub.get('success'):
                    # Update local status if different
                    stripe_status = stripe_sub['subscription']['status']
                    if subscription.get('status') != stripe_status:
                        self._update_subscription_status(
                            manufacturer_id, 
                            stripe_status
                        )
                        subscription['status'] = stripe_status
            
            return {
                'success': True,
                'subscription': self._format_subscription(subscription)
            }
            
        except Exception as e:
            logger.error(f"Error getting subscription status: {e}")
            return {
                'success': False,
                'error': 'Failed to get subscription status'
            }
    
    def create_subscription(self, manufacturer_id: str, plan_name: str, 
                          billing_cycle: str = 'monthly') -> Dict[str, Any]:
        """
        Create new subscription
        
        Args:
            manufacturer_id: Manufacturer ID
            plan_name: Plan name (starter, professional, enterprise)
            billing_cycle: monthly or yearly
            
        Returns:
            Dict with checkout session URL
        """
        try:
            if not ObjectId.is_valid(manufacturer_id):
                return {
                    'success': False,
                    'error': 'Invalid manufacturer ID'
                }
            
            # Validate plan
            if plan_name not in self.plans or plan_name == 'free':
                return {
                    'success': False,
                    'error': 'Invalid plan name'
                }
            
            if billing_cycle not in ['monthly', 'yearly']:
                return {
                    'success': False,
                    'error': 'Billing cycle must be monthly or yearly'
                }
            
            # Get manufacturer
            manufacturer = self.db.users.find_one({
                '_id': ObjectId(manufacturer_id),
                'role': 'manufacturer'
            })
            
            if not manufacturer:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            # Get or create Stripe customer
            stripe_customer_id = manufacturer.get('stripe_customer_id')
            
            if not stripe_customer_id:
                customer_result = stripe_service.create_stripe_customer(
                    manufacturer.get('primary_email') or manufacturer.get('email'),
                    manufacturer.get('current_company_name') or manufacturer.get('name'),
                    {
                        'manufacturer_id': str(manufacturer_id),
                        'role': 'manufacturer'
                    }
                )
                
                if not customer_result['success']:
                    return customer_result
                
                stripe_customer_id = customer_result['customer_id']
                
                # Update manufacturer with Stripe customer ID
                self.db.users.update_one(
                    {'_id': ObjectId(manufacturer_id)},
                    {'$set': {'stripe_customer_id': stripe_customer_id}}
                )
            
            # Create checkout session
            checkout_result = stripe_service.create_checkout_session(
                stripe_customer_id,
                plan_name,
                billing_cycle,
                {
                    'manufacturer_id': str(manufacturer_id),
                    'plan': plan_name,
                    'billing_cycle': billing_cycle
                }
            )
            
            if checkout_result['success']:
                # Create pending subscription record
                self.db.subscriptions.update_one(
                    {'manufacturer_id': ObjectId(manufacturer_id)},
                    {
                        '$set': {
                            'plan': plan_name,
                            'billing_cycle': billing_cycle,
                            'status': 'pending',
                            'stripe_customer_id': stripe_customer_id,
                            'checkout_session_id': checkout_result['session_id'],
                            'created_at': datetime.now(timezone.utc),
                            'updated_at': datetime.now(timezone.utc)
                        }
                    },
                    upsert=True
                )
            
            return checkout_result
            
        except Exception as e:
            logger.error(f"Error creating subscription: {e}")
            return {
                'success': False,
                'error': 'Failed to create subscription'
            }
    
    def upgrade_subscription(self, manufacturer_id: str, new_plan: str) -> Dict[str, Any]:
        """Upgrade to a higher plan"""
        try:
            current_sub = self.get_subscription_status(manufacturer_id)
            if not current_sub['success']:
                return current_sub
            
            current_plan = current_sub['subscription']['plan']
            
            # Validate upgrade path
            plan_hierarchy = ['free', 'starter', 'professional', 'enterprise']
            if plan_hierarchy.index(new_plan) <= plan_hierarchy.index(current_plan):
                return {
                    'success': False,
                    'error': 'Can only upgrade to higher plans'
                }
            
            subscription = self.db.subscriptions.find_one({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            if not subscription or not subscription.get('stripe_subscription_id'):
                return {
                    'success': False,
                    'error': 'No active subscription to upgrade'
                }
            
            # Update via Stripe
            price_id = stripe_service.get_stripe_price_id(
                new_plan, 
                subscription.get('billing_cycle', 'monthly')
            )
            
            result = stripe_service.update_stripe_subscription(
                subscription['stripe_subscription_id'],
                {'price_id': price_id}
            )
            
            if result['success']:
                # Update local database
                self.db.subscriptions.update_one(
                    {'manufacturer_id': ObjectId(manufacturer_id)},
                    {
                        '$set': {
                            'plan': new_plan,
                            'updated_at': datetime.now(timezone.utc)
                        }
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error upgrading subscription: {e}")
            return {
                'success': False,
                'error': 'Failed to upgrade subscription'
            }
    
    def cancel_subscription(self, manufacturer_id: str, reason: str = None) -> Dict[str, Any]:
        """Cancel subscription"""
        try:
            subscription = self.db.subscriptions.find_one({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            if not subscription:
                return {
                    'success': False,
                    'error': 'No subscription found'
                }
            
            if not subscription.get('stripe_subscription_id'):
                return {
                    'success': False,
                    'error': 'No active subscription to cancel'
                }
            
            # Cancel via Stripe
            result = stripe_service.cancel_stripe_subscription(
                subscription['stripe_subscription_id']
            )
            
            if result['success']:
                # Update local database
                self.db.subscriptions.update_one(
                    {'manufacturer_id': ObjectId(manufacturer_id)},
                    {
                        '$set': {
                            'status': 'canceled',
                            'canceled_at': datetime.now(timezone.utc),
                            'cancellation_reason': reason,
                            'updated_at': datetime.now(timezone.utc)
                        }
                    }
                )
                
                # Downgrade to free plan after current period ends
                self.db.subscriptions.update_one(
                    {'manufacturer_id': ObjectId(manufacturer_id)},
                    {'$set': {'scheduled_plan_change': 'free'}}
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error canceling subscription: {e}")
            return {
                'success': False,
                'error': 'Failed to cancel subscription'
            }
    
    def get_available_plans(self) -> List[Dict[str, Any]]:
        """Get all available subscription plans"""
        return [
            {
                'id': plan_id,
                'name': plan_data['name'],
                'price_monthly': plan_data['price_monthly'],
                'price_yearly': plan_data['price_yearly'],
                'limits': plan_data['limits'],
                'features': plan_data['features']
            }
            for plan_id, plan_data in self.plans.items()
        ]
    
    def check_plan_limits(self, manufacturer_id: str, feature: str) -> Dict[str, Any]:
        """
        Check if manufacturer has reached plan limits
        
        Args:
            manufacturer_id: Manufacturer ID
            feature: Feature to check (api_requests, products, etc.)
            
        Returns:
            Dict with limit status
        """
        try:
            subscription = self.get_subscription_status(manufacturer_id)
            if not subscription['success']:
                return subscription
            
            plan = subscription['subscription']['plan']
            limits = self.plans[plan]['limits']
            
            # Get current usage
            current_month = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0)
            
            usage_queries = {
                'api_requests': {
                    'collection': 'api_usage_logs',
                    'query': {
                        'manufacturer_id': ObjectId(manufacturer_id),
                        'timestamp': {'$gte': current_month}
                    }
                },
                'products': {
                    'collection': 'products',
                    'query': {
                        'manufacturer_id': ObjectId(manufacturer_id)
                    }
                },
                'api_keys': {
                    'collection': 'api_keys',
                    'query': {
                        'manufacturer_id': ObjectId(manufacturer_id),
                        'revoked': False
                    }
                }
            }
            
            if feature not in usage_queries:
                return {
                    'success': False,
                    'error': 'Invalid feature'
                }
            
            query_info = usage_queries[feature]
            current_usage = self.db[query_info['collection']].count_documents(
                query_info['query']
            )
            
            limit = limits.get(f'{feature}_per_month', limits.get(feature, 0))
            
            # -1 means unlimited
            if limit == -1:
                return {
                    'success': True,
                    'within_limits': True,
                    'current_usage': current_usage,
                    'limit': 'unlimited'
                }
            
            return {
                'success': True,
                'within_limits': current_usage < limit,
                'current_usage': current_usage,
                'limit': limit,
                'percentage_used': (current_usage / limit * 100) if limit > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Error checking plan limits: {e}")
            return {
                'success': False,
                'error': 'Failed to check limits'
            }
    
    def can_access_feature(self, manufacturer_id: str, feature_name: str) -> bool:
        """Check if manufacturer's plan includes a feature"""
        try:
            subscription = self.get_subscription_status(manufacturer_id)
            if not subscription['success']:
                return False
            
            plan = subscription['subscription']['plan']
            return feature_name in self.plans[plan]['features']
            
        except Exception as e:
            logger.error(f"Error checking feature access: {e}")
            return False
    
    def track_api_usage(self, manufacturer_id: str, endpoint: str) -> None:
        """Track API usage for billing purposes"""
        try:
            self.db.api_usage_logs.insert_one({
                'manufacturer_id': ObjectId(manufacturer_id),
                'endpoint': endpoint,
                'timestamp': datetime.now(timezone.utc)
            })
        except Exception as e:
            logger.error(f"Error tracking API usage: {e}")
    
    def get_usage_statistics(self, manufacturer_id: str, time_period: str = '30d') -> Dict[str, Any]:
        """Get usage statistics for manufacturer"""
        try:
            from app.utils.date_helpers import DateHelpersUtils
            
            start_date, end_date = DateHelpersUtils.get_date_range(time_period)
            
            # API usage
            api_usage = self.db.api_usage_logs.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id),
                'timestamp': {'$gte': start_date, '$lte': end_date}
            })
            
            # Products
            total_products = self.db.products.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            # Verifications
            verifications = self.db.verifications.count_documents({
                'manufacturer_id': ObjectId(manufacturer_id),
                'timestamp': {'$gte': start_date, '$lte': end_date}
            })
            
            return {
                'success': True,
                'usage': {
                    'api_requests': api_usage,
                    'total_products': total_products,
                    'verifications': verifications,
                    'period': time_period
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting usage statistics: {e}")
            return {
                'success': False,
                'error': 'Failed to get usage statistics'
            }
    
    def get_billing_history(self, manufacturer_id: str) -> Dict[str, Any]:
        """Get billing and invoice history"""
        try:
            subscription = self.db.subscriptions.find_one({
                'manufacturer_id': ObjectId(manufacturer_id)
            })
            
            if not subscription or not subscription.get('stripe_customer_id'):
                return {
                    'success': True,
                    'invoices': []
                }
            
            # Get invoices from Stripe
            invoices_result = stripe_service.get_customer_invoices(
                subscription['stripe_customer_id']
            )
            
            return invoices_result
            
        except Exception as e:
            logger.error(f"Error getting billing history: {e}")
            return {
                'success': False,
                'error': 'Failed to get billing history'
            }
    
    def _format_subscription(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Format subscription data for response"""
        plan = subscription.get('plan', 'free')
        
        return {
            'id': str(subscription['_id']),
            'plan': plan,
            'plan_name': self.plans[plan]['name'],
            'status': subscription.get('status', 'active'),
            'billing_cycle': subscription.get('billing_cycle'),
            'current_period_end': subscription.get('current_period_end'),
            'stripe_subscription_id': subscription.get('stripe_subscription_id'),
            'limits': self.plans[plan]['limits'],
            'features': self.plans[plan]['features'],
            'created_at': subscription.get('created_at'),
            'updated_at': subscription.get('updated_at')
        }
    
    def _update_subscription_status(self, manufacturer_id: str, status: str) -> None:
        """Update subscription status in database"""
        try:
            self.db.subscriptions.update_one(
                {'manufacturer_id': ObjectId(manufacturer_id)},
                {
                    '$set': {
                        'status': status,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
        except Exception as e:
            logger.error(f"Error updating subscription status: {e}")


# Singleton instance
subscription_service = SubscriptionService()