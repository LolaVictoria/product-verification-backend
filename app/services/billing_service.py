# services/billing_service.py
import os
import logging
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, Any, Optional
import stripe
from app.config.database import get_db_connection

logger = logging.getLogger(__name__)

class BillingService:
    """Stripe billing service for B2B SaaS subscriptions"""
    
    def __init__(self):
        self.db = get_db_connection()
        
        # Initialize Stripe
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        self.webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        # Subscription plans configuration
        self.plans = {
            'trial': {
                'name': 'Trial',
                'price': 0,
                'billing_cycle': 'trial',
                'features': ['1,000 API requests', '100 products', 'Basic analytics', 'Email support'],
                'limits': {
                    'api_requests_per_month': 1000,
                    'products_registered': 100,
                    'api_keys': 2,
                    'webhooks': 1
                }
            },
            'starter': {
                'name': 'Starter',
                'price_monthly': 9900,  # $99.00 in cents
                'price_annual': 99000,  # $990.00 in cents (2 months free)
                'stripe_price_monthly': os.getenv('STRIPE_PRICE_STARTER_MONTHLY'),
                'stripe_price_annual': os.getenv('STRIPE_PRICE_STARTER_ANNUAL'),
                'features': ['10,000 API requests', '1,000 products', 'Advanced analytics', 'Priority support', 'Webhooks'],
                'limits': {
                    'api_requests_per_month': 10000,
                    'products_registered': 1000,
                    'api_keys': 5,
                    'webhooks': 5
                }
            },
            'professional': {
                'name': 'Professional',
                'price_monthly': 29900,  # $299.00 in cents
                'price_annual': 299000,  # $2,990.00 in cents
                'stripe_price_monthly': os.getenv('STRIPE_PRICE_PROFESSIONAL_MONTHLY'),
                'stripe_price_annual': os.getenv('STRIPE_PRICE_PROFESSIONAL_ANNUAL'),
                'features': ['100,000 API requests', '10,000 products', 'Real-time analytics', 'Phone support', 'Custom webhooks', 'White-label options'],
                'limits': {
                    'api_requests_per_month': 100000,
                    'products_registered': 10000,
                    'api_keys': 20,
                    'webhooks': 20
                }
            },
            'enterprise': {
                'name': 'Enterprise',
                'price_monthly': 99900,  # $999.00 in cents
                'price_annual': 999000,  # $9,990.00 in cents
                'stripe_price_monthly': os.getenv('STRIPE_PRICE_ENTERPRISE_MONTHLY'),
                'stripe_price_annual': os.getenv('STRIPE_PRICE_ENTERPRISE_ANNUAL'),
                'features': ['Unlimited API requests', 'Unlimited products', 'Custom analytics', 'Dedicated support', 'SLA guarantee', 'On-premise deployment'],
                'limits': {
                    'api_requests_per_month': float('inf'),
                    'products_registered': float('inf'),
                    'api_keys': 100,
                    'webhooks': 100
                }
            }
        }
    
    def get_available_plans(self) -> Dict[str, Any]:
        """Get all available subscription plans"""
        return {
            'plans': self.plans,
            'currency': 'USD',
            'billing_cycles': ['monthly', 'annual']
        }
     
    def _create_default_billing_record(self, user_id: ObjectId, manufacturer: Dict[str, Any]) -> Dict[str, Any]:
        """Create default billing record for existing manufacturer"""
        try:
            # Calculate trial period
            created_at = manufacturer.get('created_at', datetime.now(timezone.utc))
            trial_ends = created_at + timedelta(days=14)
            
            billing_doc = {
                'user_id': user_id,
                'subscription_status': 'trial',
                'plan': 'trial',
                'billing_cycle': 'trial',
                'trial_starts': created_at,
                'trial_ends': trial_ends,
                'usage_limits': self.plans['trial']['limits'].copy(),
                'usage_current': {
                    'api_requests': 0,
                    'products_registered': 0,
                    'api_keys': 1
                },
                'stripe_customer_id': None,
                'stripe_subscription_id': None,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            self.db.billing.insert_one(billing_doc)
            return billing_doc
            
        except Exception as e:
            logger.error(f"Error creating default billing record: {e}")
            raise
    
    def _get_current_usage(self, user_id: ObjectId) -> Dict[str, Any]:
        """Get manufacturer's current usage statistics"""
        try:
            current_month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # API usage this month
            api_usage = self.db.api_usage_logs.count_documents({
                'manufacturer_id': user_id,
                'timestamp': {'$gte': current_month_start}
            })
            
            # Products registered total
            products_registered = self.db.products.count_documents({
                'manufacturer_id': user_id
            })
            
            # Active API keys
            active_api_keys = self.db.api_keys.count_documents({
                'manufacturer_id': user_id,
                'revoked': False
            })
            
            # Active webhooks
            active_webhooks = self.db.webhooks.count_documents({
                'manufacturer_id': user_id,
                'active': True
            }) if 'webhooks' in self.db.list_collection_names() else 0
            
            return {
                'api_requests_this_month': api_usage,
                'products_registered_total': products_registered,
                'api_keys_active': active_api_keys,
                'webhooks_active': active_webhooks,
                'last_calculated': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting current usage: {e}")
            return {
                'api_requests_this_month': 0,
                'products_registered_total': 0,
                'api_keys_active': 0,
                'webhooks_active': 0
            }
    
    async def create_checkout_session(self, user_id: ObjectId, plan: str, billing_cycle: str = 'monthly') -> Dict[str, Any]:
        """Create Stripe checkout session for subscription upgrade"""
        try:
            # Validate plan
            if plan not in self.plans or plan == 'trial':
                return {
                    'success': False,
                    'error': 'Invalid subscription plan'
                }
            
            # Validate billing cycle
            if billing_cycle not in ['monthly', 'annual']:
                return {
                    'success': False,
                    'error': 'Invalid billing cycle'
                }
            
            # Get manufacturer info
            manufacturer = self.db.users.find_one({'_id': user_id, 'role': 'manufacturer'})
            if not manufacturer:
                return {
                    'success': False,
                    'error': 'Manufacturer not found'
                }
            
            # Get or create Stripe customer
            stripe_customer_id = await self._get_or_create_stripe_customer(manufacturer)
            
            # Get price ID
            price_key = f'stripe_price_{billing_cycle}'
            price_id = self.plans[plan].get(price_key)
            
            if not price_id:
                return {
                    'success': False,
                    'error': f'Price ID not configured for {plan} {billing_cycle}'
                }
            
            # Create checkout session
            try:
                session = stripe.checkout.Session.create(
                    customer=stripe_customer_id,
                    payment_method_types=['card'],
                    line_items=[{
                        'price': price_id,
                        'quantity': 1,
                    }],
                    mode='subscription',
                    success_url=f"{os.getenv('FRONTEND_URL')}/dashboard/manufacturer/{user_id}?session_id={{CHECKOUT_SESSION_ID}}",
                    cancel_url=f"{os.getenv('FRONTEND_URL')}/dashboard/manufacturer/{user_id}/billing",
                    metadata={
                        'user_id': str(user_id),
                        'plan': plan,
                        'billing_cycle': billing_cycle
                    },
                    subscription_data={
                        'metadata': {
                            'user_id': str(user_id),
                            'plan': plan,
                            'billing_cycle': billing_cycle
                        }
                    }
                )
                
                return {
                    'success': True,
                    'checkout_url': session.url,
                    'session_id': session.id
                }
                
            except stripe.error.StripeError as e:
                logger.error(f"Stripe checkout session error: {e}")
                return {
                    'success': False,
                    'error': f'Failed to create checkout session: {str(e)}'
                }
            
        except Exception as e:
            logger.error(f"Create checkout session error: {e}")
            return {
                'success': False,
                'error': 'Failed to create checkout session'
            }
    
    async def _get_or_create_stripe_customer(self, manufacturer: Dict[str, Any]) -> str:
        """Get existing or create new Stripe customer"""
        try:
            # Check if customer already exists
            billing_info = self.db.billing.find_one({'user_id': manufacturer['_id']})
            
            if billing_info and billing_info.get('stripe_customer_id'):
                # Verify customer exists in Stripe
                try:
                    customer = stripe.Customer.retrieve(billing_info['stripe_customer_id'])
                    return customer.id
                except stripe.error.InvalidRequestError:
                    # Customer doesn't exist in Stripe, create new one
                    pass
            
            # Create new Stripe customer
            customer = stripe.Customer.create(
                email=manufacturer.get('primary_email'),
                name=manufacturer.get('name', manufacturer.get('current_company_name')),
                metadata={
                    'user_id': str(manufacturer['_id']),
                    'company_name': manufacturer.get('current_company_name'),
                    'role': 'manufacturer'
                }
            )
            
            # Update billing record with customer ID
            self.db.billing.update_one(
                {'user_id': manufacturer['_id']},
                {
                    '$set': {
                        'stripe_customer_id': customer.id,
                        'updated_at': datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )
            
            return customer.id
            
        except Exception as e:
            logger.error(f"Error creating Stripe customer: {e}")
            raise
    
    def handle_webhook_event(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """Handle Stripe webhook events"""
        try:
            # Verify webhook signature
            try:
                event = stripe.Webhook.construct_event(
                    payload, signature, self.webhook_secret
                )
            except ValueError:
                return {'success': False, 'error': 'Invalid payload'}
            except stripe.error.SignatureVerificationError:
                return {'success': False, 'error': 'Invalid signature'}
            
            # Handle the event
            if event['type'] == 'checkout.session.completed':
                return self._handle_checkout_completed(event['data']['object'])
            
            elif event['type'] == 'invoice.payment_succeeded':
                return self._handle_payment_succeeded(event['data']['object'])
            
            elif event['type'] == 'invoice.payment_failed':
                return self._handle_payment_failed(event['data']['object'])
            
            elif event['type'] == 'customer.subscription.updated':
                return self._handle_subscription_updated(event['data']['object'])
            
            elif event['type'] == 'customer.subscription.deleted':
                return self._handle_subscription_deleted(event['data']['object'])
            
            else:
                logger.info(f"Unhandled webhook event type: {event['type']}")
                return {'success': True, 'message': 'Event not handled'}
            
        except Exception as e:
            logger.error(f"Webhook handling error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle webhook event'
            }
    
    def _handle_checkout_completed(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Handle successful checkout completion"""
        try:
            user_id = session['metadata']['user_id']
            plan = session['metadata']['plan']
            billing_cycle = session['metadata']['billing_cycle']
            
            # Get subscription from Stripe
            subscription = stripe.Subscription.retrieve(session['subscription'])
            
            # Update billing record
            update_data = {
                'subscription_status': 'active',
                'plan': plan,
                'billing_cycle': billing_cycle,
                'stripe_subscription_id': subscription.id,
                'stripe_customer_id': subscription.customer,
                'current_period_start': datetime.fromtimestamp(subscription.current_period_start, tz=timezone.utc),
                'current_period_end': datetime.fromtimestamp(subscription.current_period_end, tz=timezone.utc),
                'next_billing_date': datetime.fromtimestamp(subscription.current_period_end, tz=timezone.utc),
                'usage_limits': self.plans[plan]['limits'].copy(),
                'updated_at': datetime.now(timezone.utc)
            }
            
            self.db.billing.update_one(
                {'user_id': ObjectId(user_id)},
                {'$set': update_data}
            )
            
            # Update user account status
            self.db.users.update_one(
                {'_id': ObjectId(user_id)},
                {
                    '$set': {
                        'account_status': 'active',
                        'subscription_status': 'active',
                        'subscription_plan': plan,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            logger.info(f"Subscription activated for user {user_id}: {plan} {billing_cycle}")
            
            return {
                'success': True,
                'message': f'Subscription activated: {plan} {billing_cycle}'
            }
            
        except Exception as e:
            logger.error(f"Handle checkout completed error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle checkout completion'
            }
    
    def _handle_payment_succeeded(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle successful payment"""
        try:
            subscription_id = invoice['subscription']
            
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                user_id = subscription['metadata'].get('user_id')
                
                if user_id:
                    # Update next billing date
                    self.db.billing.update_one(
                        {'user_id': ObjectId(user_id)},
                        {
                            '$set': {
                                'next_billing_date': datetime.fromtimestamp(subscription.current_period_end, tz=timezone.utc),
                                'last_payment_date': datetime.now(timezone.utc),
                                'updated_at': datetime.now(timezone.utc)
                            }
                        }
                    )
                    
                    logger.info(f"Payment succeeded for user {user_id}")
            
            return {
                'success': True,
                'message': 'Payment processed successfully'
            }
            
        except Exception as e:
            logger.error(f"Handle payment succeeded error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle payment success'
            }
    
    def _handle_payment_failed(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle failed payment"""
        try:
            subscription_id = invoice['subscription']
            
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                user_id = subscription['metadata'].get('user_id')
                
                if user_id:
                    # Update billing status
                    self.db.billing.update_one(
                        {'user_id': ObjectId(user_id)},
                        {
                            '$set': {
                                'payment_status': 'failed',
                                'last_payment_attempt': datetime.now(timezone.utc),
                                'updated_at': datetime.now(timezone.utc)
                            }
                        }
                    )
                    
                    logger.warning(f"Payment failed for user {user_id}")
            
            return {
                'success': True,
                'message': 'Payment failure recorded'
            }
            
        except Exception as e:
            logger.error(f"Handle payment failed error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle payment failure'
            }
    
    def _handle_subscription_updated(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updates"""
        try:
            user_id = subscription['metadata'].get('user_id')
            
            if user_id:
                # Determine plan from price ID
                plan = self._get_plan_from_price_id(subscription['items']['data'][0]['price']['id'])
                
                update_data = {
                    'subscription_status': subscription['status'],
                    'plan': plan,
                    'current_period_start': datetime.fromtimestamp(subscription['current_period_start'], tz=timezone.utc),
                    'current_period_end': datetime.fromtimestamp(subscription['current_period_end'], tz=timezone.utc),
                    'next_billing_date': datetime.fromtimestamp(subscription['current_period_end'], tz=timezone.utc),
                    'updated_at': datetime.now(timezone.utc)
                }
                
                if plan:
                    update_data['usage_limits'] = self.plans[plan]['limits'].copy()
                
                self.db.billing.update_one(
                    {'user_id': ObjectId(user_id)},
                    {'$set': update_data}
                )
                
                logger.info(f"Subscription updated for user {user_id}: {subscription['status']}")
            
            return {
                'success': True,
                'message': 'Subscription updated successfully'
            }
            
        except Exception as e:
            logger.error(f"Handle subscription updated error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle subscription update'
            }
    
    def _handle_subscription_deleted(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription cancellation"""
        try:
            user_id = subscription['metadata'].get('user_id')
            
            if user_id:
                # Update to cancelled status
                self.db.billing.update_one(
                    {'user_id': ObjectId(user_id)},
                    {
                        '$set': {
                            'subscription_status': 'cancelled',
                            'plan': 'trial',  # Revert to trial limits
                            'usage_limits': self.plans['trial']['limits'].copy(),
                            'cancellation_date': datetime.now(timezone.utc),
                            'updated_at': datetime.now(timezone.utc)
                        }
                    }
                )
                
                # Update user account status
                self.db.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {
                        '$set': {
                            'account_status': 'cancelled',
                            'subscription_status': 'cancelled',
                            'subscription_plan': 'trial',
                            'updated_at': datetime.now(timezone.utc)
                        }
                    }
                )
                
                logger.info(f"Subscription cancelled for user {user_id}")
            
            return {
                'success': True,
                'message': 'Subscription cancellation processed'
            }
            
        except Exception as e:
            logger.error(f"Handle subscription deleted error: {e}")
            return {
                'success': False,
                'error': 'Failed to handle subscription cancellation'
            }
    
    def _get_plan_from_price_id(self, price_id: str) -> Optional[str]:
        """Get plan name from Stripe price ID"""
        for plan_name, plan_config in self.plans.items():
            if plan_config.get('stripe_price_monthly') == price_id:
                return plan_name
            if plan_config.get('stripe_price_annual') == price_id:
                return plan_name
        return None
    
    def check_usage_limits(self, user_id: ObjectId, resource_type: str, amount: int = 1) -> Dict[str, Any]:
        """Check if user has exceeded usage limits"""
        try:
            # Get subscription info
            subscription_result = self.get_subscription_status(user_id)
            if not subscription_result['success']:
                return {'success': False, 'error': 'Could not check subscription'}
            
            subscription = subscription_result['subscription']
            limits = subscription.get('limits', {})
            usage = subscription.get('usage', {})
            
            # Check specific resource limits
            if resource_type == 'api_requests':
                limit = limits.get('api_requests_per_month', 0)
                current_usage = usage.get('api_requests_this_month', 0)
                
                if current_usage + amount > limit:
                    return {
                        'success': False,
                        'exceeded': True,
                        'limit': limit,
                        'current_usage': current_usage,
                        'requested_amount': amount,
                        'message': f'API request limit exceeded. Current: {current_usage}, Limit: {limit}'
                    }
            
            elif resource_type == 'products':
                limit = limits.get('products_registered', 0)
                current_usage = usage.get('products_registered_total', 0)
                
                if current_usage + amount > limit:
                    return {
                        'success': False,
                        'exceeded': True,
                        'limit': limit,
                        'current_usage': current_usage,
                        'requested_amount': amount,
                        'message': f'Product limit exceeded. Current: {current_usage}, Limit: {limit}'
                    }
            
            elif resource_type == 'api_keys':
                limit = limits.get('api_keys', 0)
                current_usage = usage.get('api_keys_active', 0)
                
                if current_usage + amount > limit:
                    return {
                        'success': False,
                        'exceeded': True,
                        'limit': limit,
                        'current_usage': current_usage,
                        'requested_amount': amount,
                        'message': f'API key limit exceeded. Current: {current_usage}, Limit: {limit}'
                    }
            
            return {
                'success': True,
                'exceeded': False,
                'limit': limits.get(f'{resource_type}_per_month' if resource_type == 'api_requests' else resource_type, 0),
                'current_usage': usage.get(f'{resource_type}_this_month' if resource_type == 'api_requests' else f'{resource_type}_active', 0)
            }
            
        except Exception as e:
            logger.error(f"Check usage limits error: {e}")
            return {
                'success': False,
                'error': 'Failed to check usage limits'
            }
    
    def record_usage(self, user_id: ObjectId, resource_type: str, amount: int = 1) -> Dict[str, Any]:
        """Record resource usage"""
        try:
            # Update usage in API usage logs for API requests
            if resource_type == 'api_requests':
                usage_doc = {
                    'manufacturer_id': user_id,
                    'timestamp': datetime.now(timezone.utc),
                    'endpoint': 'api_usage',
                    'requests_count': amount
                }
                self.db.api_usage_logs.insert_one(usage_doc)
            
            return {'success': True, 'message': f'Usage recorded: {resource_type} +{amount}'}
            
        except Exception as e:
            logger.error(f"Record usage error: {e}")
            return {
                'success': False,
                'error': 'Failed to record usage'
            }


# Singleton instance
billing_service = BillingService()