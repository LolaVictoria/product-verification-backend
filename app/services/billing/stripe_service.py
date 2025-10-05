"""
Stripe Service
Direct Stripe API integration for payment processing
"""

import stripe
import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from bson import ObjectId

from app.config.database import get_db_connection

logger = logging.getLogger(__name__)

# Configure Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')


class StripeService:
    """Handles all Stripe API operations"""
    
    def __init__(self):
        self.webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        self.db = get_db_connection()
        
        # Price IDs mapping (you should get these from Stripe Dashboard)
        self.price_ids = {
            'starter_monthly': os.getenv('STRIPE_PRICE_STARTER_MONTHLY'),
            'starter_yearly': os.getenv('STRIPE_PRICE_STARTER_YEARLY'),
            'professional_monthly': os.getenv('STRIPE_PRICE_PROFESSIONAL_MONTHLY'),
            'professional_yearly': os.getenv('STRIPE_PRICE_PROFESSIONAL_YEARLY'),
            'enterprise_monthly': os.getenv('STRIPE_PRICE_ENTERPRISE_MONTHLY'),
            'enterprise_yearly': os.getenv('STRIPE_PRICE_ENTERPRISE_YEARLY'),
        }
    
    def create_stripe_customer(self, email: str, name: str, metadata: Dict[str, str]) -> Dict[str, Any]:
        """
        Create Stripe customer
        
        Args:
            email: Customer email
            name: Customer name
            metadata: Additional metadata
            
        Returns:
            Dict with customer ID
        """
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata=metadata
            )
            
            logger.info(f"Created Stripe customer: {customer.id}")
            
            return {
                'success': True,
                'customer_id': customer.id,
                'customer': customer
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe customer creation error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_stripe_customer(self, customer_id: str) -> Dict[str, Any]:
        """Get Stripe customer details"""
        try:
            customer = stripe.Customer.retrieve(customer_id)
            
            return {
                'success': True,
                'customer': customer
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe customer retrieval error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_checkout_session(self, customer_id: str, plan_name: str, 
                                billing_cycle: str, metadata: Dict[str, str]) -> Dict[str, Any]:
        """
        Create Stripe checkout session
        
        Args:
            customer_id: Stripe customer ID
            plan_name: Plan name (starter, professional, enterprise)
            billing_cycle: monthly or yearly
            metadata: Session metadata
            
        Returns:
            Dict with checkout session URL
        """
        try:
            price_id = self.get_stripe_price_id(plan_name, billing_cycle)
            
            if not price_id:
                return {
                    'success': False,
                    'error': 'Invalid plan or billing cycle'
                }
            
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1
                }],
                mode='subscription',
                success_url=f"{os.getenv('FRONTEND_URL')}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{os.getenv('FRONTEND_URL')}/billing/cancel",
                metadata=metadata,
                allow_promotion_codes=True,
                billing_address_collection='required'
            )
            
            logger.info(f"Created checkout session: {session.id}")
            
            return {
                'success': True,
                'session_id': session.id,
                'checkout_url': session.url
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe checkout session error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_portal_session(self, customer_id: str, return_url: str = None) -> Dict[str, Any]:
        """Create Stripe customer portal session for managing subscription"""
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url or f"{os.getenv('FRONTEND_URL')}/dashboard/billing"
            )
            
            return {
                'success': True,
                'portal_url': session.url
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe portal session error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_stripe_subscription(self, customer_id: str, price_id: str) -> Dict[str, Any]:
        """Create Stripe subscription directly"""
        try:
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{'price': price_id}],
                payment_behavior='default_incomplete',
                expand=['latest_invoice.payment_intent']
            )
            
            return {
                'success': True,
                'subscription': subscription,
                'subscription_id': subscription.id
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription creation error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def retrieve_stripe_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Retrieve Stripe subscription details"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            return {
                'success': True,
                'subscription': {
                    'id': subscription.id,
                    'status': subscription.status,
                    'current_period_end': subscription.current_period_end,
                    'cancel_at_period_end': subscription.cancel_at_period_end,
                    'items': subscription['items']['data']
                }
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription retrieval error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_stripe_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update Stripe subscription"""
        try:
            subscription = stripe.Subscription.modify(
                subscription_id,
                **updates
            )
            
            logger.info(f"Updated subscription: {subscription_id}")
            
            return {
                'success': True,
                'subscription': subscription
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription update error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def cancel_stripe_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Cancel Stripe subscription"""
        try:
            subscription = stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True
            )
            
            logger.info(f"Canceled subscription: {subscription_id}")
            
            return {
                'success': True,
                'subscription': subscription,
                'message': 'Subscription will be canceled at the end of the billing period'
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription cancellation error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_customer_invoices(self, customer_id: str, limit: int = 10) -> Dict[str, Any]:
        """Get customer invoices from Stripe"""
        try:
            invoices = stripe.Invoice.list(
                customer=customer_id,
                limit=limit
            )
            
            formatted_invoices = [
                {
                    'id': invoice.id,
                    'amount': invoice.amount_paid / 100,  # Convert from cents
                    'currency': invoice.currency,
                    'status': invoice.status,
                    'invoice_pdf': invoice.invoice_pdf,
                    'created': invoice.created,
                    'period_start': invoice.period_start,
                    'period_end': invoice.period_end
                }
                for invoice in invoices.data
            ]
            
            return {
                'success': True,
                'invoices': formatted_invoices
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Error fetching invoices: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_stripe_price_id(self, plan_name: str, billing_cycle: str) -> Optional[str]:
        """Get Stripe price ID for plan and billing cycle"""
        key = f"{plan_name}_{billing_cycle}"
        return self.price_ids.get(key)
    
    def handle_webhook_event(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """
        Process Stripe webhook events
        
        Args:
            payload: Raw webhook payload
            signature: Stripe signature header
            
        Returns:
            Dict with processing result
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
            
            logger.info(f"Received Stripe webhook: {event['type']}")
            
            # Route to specific handlers
            handlers = {
                'checkout.session.completed': self.process_checkout_completed,
                'customer.subscription.created': self.process_subscription_created,
                'customer.subscription.updated': self.process_subscription_updated,
                'customer.subscription.deleted': self.process_subscription_deleted,
                'invoice.paid': self.process_invoice_paid,
                'invoice.payment_failed': self.process_invoice_payment_failed,
                'payment_method.attached': self.process_payment_method_attached,
            }
            
            handler = handlers.get(event['type'])
            if handler:
                return handler(event['data']['object'])
            
            return {
                'success': True,
                'message': f"Event {event['type']} received but not handled"
            }
            
        except stripe.error.SignatureVerificationError:
            logger.error("Invalid webhook signature")
            return {
                'success': False,
                'error': 'Invalid signature'
            }
        except Exception as e:
            logger.error(f"Webhook processing error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_checkout_completed(self, session) -> Dict[str, Any]:
        """Process checkout.session.completed event"""
        try:
            logger.info(f"Processing checkout completion: {session.id}")
            
            manufacturer_id = session.metadata.get('manufacturer_id')
            plan = session.metadata.get('plan')
            billing_cycle = session.metadata.get('billing_cycle')
            
            if not manufacturer_id:
                logger.error("No manufacturer_id in session metadata")
                return {'success': False, 'error': 'Missing manufacturer_id'}
            
            # Update subscription in database
            self.db.subscriptions.update_one(
                {'manufacturer_id': ObjectId(manufacturer_id)},
                {
                    '$set': {
                        'status': 'active',
                        'stripe_subscription_id': session.subscription,
                        'stripe_customer_id': session.customer,
                        'plan': plan,
                        'billing_cycle': billing_cycle,
                        'activated_at': datetime.now(timezone.utc),
                        'updated_at': datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )
            
            # Send notification
            try:
                from app.services.notification_service import notification_service
                notification_service.notify_subscription_activated(manufacturer_id, plan)
            except Exception as e:
                logger.warning(f"Failed to send notification: {e}")
            
            return {
                'success': True,
                'message': 'Checkout completed'
            }
            
        except Exception as e:
            logger.error(f"Error processing checkout completion: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_subscription_created(self, subscription) -> Dict[str, Any]:
        """Process customer.subscription.created event"""
        try:
            logger.info(f"Processing subscription created: {subscription.id}")
            
            customer_id = subscription.customer
            
            # Find manufacturer by Stripe customer ID
            manufacturer = self.db.users.find_one({
                'stripe_customer_id': customer_id,
                'role': 'manufacturer'
            })
            
            if not manufacturer:
                logger.warning(f"Manufacturer not found for customer: {customer_id}")
                return {'success': False, 'error': 'Manufacturer not found'}
            
            # Extract plan info from subscription
            plan_name = self._extract_plan_from_subscription(subscription)
            
            # Update subscription record
            self.db.subscriptions.update_one(
                {'manufacturer_id': manufacturer['_id']},
                {
                    '$set': {
                        'stripe_subscription_id': subscription.id,
                        'status': subscription.status,
                        'current_period_start': datetime.fromtimestamp(subscription.current_period_start, tz=timezone.utc),
                        'current_period_end': datetime.fromtimestamp(subscription.current_period_end, tz=timezone.utc),
                        'plan': plan_name,
                        'updated_at': datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )
            
            return {
                'success': True,
                'message': 'Subscription created'
            }
            
        except Exception as e:
            logger.error(f"Error processing subscription created: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_subscription_updated(self, subscription) -> Dict[str, Any]:
        """Process customer.subscription.updated event"""
        try:
            logger.info(f"Processing subscription updated: {subscription.id}")
            
            # Find subscription in database
            existing_sub = self.db.subscriptions.find_one({
                'stripe_subscription_id': subscription.id
            })
            
            if not existing_sub:
                logger.warning(f"Subscription not found in database: {subscription.id}")
                return {'success': False, 'error': 'Subscription not found'}
            
            # Extract plan info
            plan_name = self._extract_plan_from_subscription(subscription)
            
            # Update subscription
            update_data = {
                'status': subscription.status,
                'current_period_start': datetime.fromtimestamp(subscription.current_period_start, tz=timezone.utc),
                'current_period_end': datetime.fromtimestamp(subscription.current_period_end, tz=timezone.utc),
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'updated_at': datetime.now(timezone.utc)
            }
            
            if plan_name:
                update_data['plan'] = plan_name
            
            self.db.subscriptions.update_one(
                {'stripe_subscription_id': subscription.id},
                {'$set': update_data}
            )
            
            # If subscription was canceled
            if subscription.cancel_at_period_end:
                manufacturer_id = existing_sub['manufacturer_id']
                try:
                    from app.services.notification_service import notification_service
                    notification_service.notify_subscription_canceled(str(manufacturer_id))
                except Exception as e:
                    logger.warning(f"Failed to send notification: {e}")
            
            return {
                'success': True,
                'message': 'Subscription updated'
            }
            
        except Exception as e:
            logger.error(f"Error processing subscription updated: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_subscription_deleted(self, subscription) -> Dict[str, Any]:
        """Process customer.subscription.deleted event"""
        try:
            logger.info(f"Processing subscription deleted: {subscription.id}")
            
            # Find and update subscription
            result = self.db.subscriptions.update_one(
                {'stripe_subscription_id': subscription.id},
                {
                    '$set': {
                        'status': 'canceled',
                        'canceled_at': datetime.now(timezone.utc),
                        'plan': 'free',  # Downgrade to free
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if result.matched_count > 0:
                # Get manufacturer to send notification
                sub_record = self.db.subscriptions.find_one({
                    'stripe_subscription_id': subscription.id
                })
                
                if sub_record:
                    manufacturer_id = sub_record['manufacturer_id']
                    try:
                        from app.services.notification_service import notification_service
                        notification_service.notify_subscription_ended(str(manufacturer_id))
                    except Exception as e:
                        logger.warning(f"Failed to send notification: {e}")
            
            return {
                'success': True,
                'message': 'Subscription deleted'
            }
            
        except Exception as e:
            logger.error(f"Error processing subscription deleted: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_invoice_paid(self, invoice) -> Dict[str, Any]:
        """Process invoice.paid event"""
        try:
            logger.info(f"Processing invoice paid: {invoice.id}")
            
            # Log successful payment
            self.db.payment_logs.insert_one({
                'invoice_id': invoice.id,
                'customer_id': invoice.customer,
                'subscription_id': invoice.subscription,
                'amount': invoice.amount_paid / 100,
                'currency': invoice.currency,
                'status': 'paid',
                'paid_at': datetime.fromtimestamp(invoice.status_transitions.paid_at, tz=timezone.utc) if invoice.status_transitions.paid_at else datetime.now(timezone.utc),
                'created_at': datetime.now(timezone.utc)
            })
            
            return {
                'success': True,
                'message': 'Invoice paid'
            }
            
        except Exception as e:
            logger.error(f"Error processing invoice paid: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_invoice_payment_failed(self, invoice) -> Dict[str, Any]:
        """Process invoice.payment_failed event"""
        try:
            logger.warning(f"Processing invoice payment failed: {invoice.id}")
            
            # Log failed payment
            self.db.payment_logs.insert_one({
                'invoice_id': invoice.id,
                'customer_id': invoice.customer,
                'subscription_id': invoice.subscription,
                'amount': invoice.amount_due / 100,
                'currency': invoice.currency,
                'status': 'failed',
                'failure_reason': 'Payment failed',
                'created_at': datetime.now(timezone.utc)
            })
            
            # Find manufacturer and send notification
            manufacturer = self.db.users.find_one({
                'stripe_customer_id': invoice.customer,
                'role': 'manufacturer'
            })
            
            if manufacturer:
                try:
                    from app.services.notification_service import notification_service
                    notification_service.notify_payment_failed(str(manufacturer['_id']), invoice.amount_due / 100)
                except Exception as e:
                    logger.warning(f"Failed to send notification: {e}")
            
            return {
                'success': True,
                'message': 'Invoice payment failed logged'
            }
            
        except Exception as e:
            logger.error(f"Error processing invoice payment failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_payment_method_attached(self, payment_method) -> Dict[str, Any]:
        """Process payment_method.attached event"""
        try:
            logger.info(f"Processing payment method attached: {payment_method.id}")
            
            # Update customer's default payment method if needed
            customer_id = payment_method.customer
            
            # You can store payment method details if needed
            self.db.payment_methods.update_one(
                {'customer_id': customer_id},
                {
                    '$set': {
                        'payment_method_id': payment_method.id,
                        'type': payment_method.type,
                        'card_brand': payment_method.card.brand if payment_method.type == 'card' else None,
                        'card_last4': payment_method.card.last4 if payment_method.type == 'card' else None,
                        'updated_at': datetime.now(timezone.utc)
                    }
                },
                upsert=True
            )
            
            return {
                'success': True,
                'message': 'Payment method attached'
            }
            
        except Exception as e:
            logger.error(f"Error processing payment method attached: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_plan_from_subscription(self, subscription) -> Optional[str]:
        """Extract plan name from Stripe subscription"""
        try:
            if subscription.items and len(subscription.items.data) > 0:
                price_id = subscription.items.data[0].price.id
                
                # Reverse lookup price_id to plan name
                for key, value in self.price_ids.items():
                    if value == price_id:
                        # Extract plan name (e.g., 'starter_monthly' -> 'starter')
                        return key.rsplit('_', 1)[0]
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting plan from subscription: {e}")
            return None


# Singleton instance
stripe_service = StripeService()