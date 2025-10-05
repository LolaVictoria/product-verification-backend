"""
Onboarding Service
B2B SaaS onboarding for manufacturer self-service registration
"""

import logging
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from typing import Dict, Any, Optional, List

from app.config.database import get_db_connection
from app.utils.password_utils import hash_password
from app.services.notification_service import notification_service
from app.validators.manufacturer_validator import ManufacturerValidator

logger = logging.getLogger(__name__)


class OnboardingService:
    """B2B SaaS onboarding service for manufacturer self-service registration"""
    
    def __init__(self):
        self.db = get_db_connection()
        self.trial_days = 14
        self.validator = ManufacturerValidator()
    
    def register_manufacturer(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Self-service manufacturer registration with instant sandbox access
        Following modern B2B SaaS patterns
        """
        try:
            # Validate registration data
            validation_result = self.validator.validate_manufacturer_data(registration_data)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': 'Validation failed',
                    'field_errors': validation_result['errors']
                }
            
            email = registration_data['email'].lower().strip()
            company_name = registration_data['company_name'].strip()
            
            # Check if manufacturer already exists
            existing_user = self.db.users.find_one({
                '$or': [
                    {'primary_email': email},
                    {'emails.email': email}
                ],
                'role': 'manufacturer'
            })
            
            if existing_user:
                return {
                    'success': False,
                    'error': 'An account with this email already exists',
                    'existing_account': True
                }
            
            # Check if company name is already taken
            existing_company = self.db.users.find_one({
                'current_company_name': company_name,
                'role': 'manufacturer'
            })
            
            if existing_company:
                return {
                    'success': False,
                    'error': 'A manufacturer with this company name already exists',
                    'field_errors': {'company_name': 'Company name is already taken'}
                }
            
            # Create trial end date
            trial_expires = datetime.now(timezone.utc) + timedelta(days=self.trial_days)
            
            # Generate verification token
            verification_token = secrets.token_urlsafe(32)
            
            # Create manufacturer document
            manufacturer_doc = {
                'role': 'manufacturer',
                'primary_email': email,
                'emails': [{'email': email, 'verified': False, 'is_primary': True}],
                'password_hash': hash_password(registration_data['password']),
                'name': registration_data.get('name', ''),
                'current_company_name': company_name,
                'company_names': [{'name': company_name, 'is_current': True}],
                'company_size': registration_data.get('company_size', 'unknown'),
                'industry': registration_data.get('industry', 'unknown'),
                'country': registration_data.get('country', 'unknown'),
                'website': registration_data.get('website', ''),
                'phone': registration_data.get('phone', ''),
                
                # Account status
                'verification_status': 'pending',
                'email_verified': False,
                'account_status': 'trial',
                'is_active': True,
                
                # Trial information
                'trial_starts': datetime.now(timezone.utc),
                'trial_expires': trial_expires,
                'trial_days': self.trial_days,
                
                # Subscription info
                'subscription_status': 'trial',
                'subscription_plan': 'trial',
                'billing_status': 'trial',
                
                # Onboarding progress
                'onboarding_completed': False,
                'onboarding_steps': {
                    'email_verified': False,
                    'first_api_call': False,
                    'first_product_registered': False,
                    'integration_completed': False,
                    'documentation_viewed': False
                },
                
                # Registration metadata
                'registration_source': registration_data.get('referral_source', 'direct'),
                'registration_ip': registration_data.get('ip_address', ''),
                'registration_user_agent': registration_data.get('user_agent', ''),
                
                # Timestamps
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc)
            }
            
            # Insert manufacturer
            result = self.db.users.insert_one(manufacturer_doc)
            user_id = result.inserted_id
            
            # Create company record
            company_doc = {
                'name': company_name,
                'owner_id': user_id,
                'industry': registration_data.get('industry', 'unknown'),
                'size': registration_data.get('company_size', 'unknown'),
                'website': registration_data.get('website', ''),
                'country': registration_data.get('country', 'unknown'),
                'status': 'active',
                'trial_expires': trial_expires,
                'created_at': datetime.now(timezone.utc)
            }
            
            company_result = self.db.companies.insert_one(company_doc)
            company_id = company_result.inserted_id
            
            # Generate sandbox API key instantly
            api_key_result = self._create_sandbox_api_key(user_id, company_name)
            
            if not api_key_result['success']:
                # Rollback user creation if API key fails
                self.db.users.delete_one({'_id': user_id})
                self.db.companies.delete_one({'_id': company_id})
                return {
                    'success': False,
                    'error': 'Failed to create API key'
                }
            
            # Create initial billing record
            billing_doc = {
                'user_id': user_id,
                'company_id': company_id,
                'subscription_status': 'trial',
                'plan': 'trial',
                'billing_cycle': 'monthly',
                'trial_starts': datetime.now(timezone.utc),
                'trial_ends': trial_expires,
                'usage_limits': {
                    'api_requests_per_month': 1000,
                    'products_registered': 100,
                    'api_keys': 2
                },
                'usage_current': {
                    'api_requests': 0,
                    'products_registered': 0,
                    'api_keys': 1
                },
                'stripe_customer_id': None,
                'stripe_subscription_id': None,
                'created_at': datetime.now(timezone.utc)
            }
            
            self.db.billing.insert_one(billing_doc)
            
            # Store verification token
            token_doc = {
                'user_id': user_id,
                'token': verification_token,
                'type': 'email_verification',
                'email': email,
                'used': False,
                'created_at': datetime.now(timezone.utc),
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=24)
            }
            self.db.verification_tokens.insert_one(token_doc)
            
            # Send welcome email with verification
            try:
                email_result = notification_service.send_welcome_email(
                    email, 
                    company_name, 
                    verification_token
                )
                if not email_result['success']:
                    logger.warning(f"Welcome email failed for {email}: {email_result.get('error')}")
            except Exception as e:
                logger.warning(f"Welcome email failed: {e}")
            
            return {
                'success': True,
                'message': 'Account created successfully! Check your email for verification.',
                'user_id': str(user_id),
                'company_id': str(company_id),
                'trial_expires': trial_expires.isoformat(),
                'api_key': {
                    'sandbox': api_key_result.get('api_key'),
                    'key_id': api_key_result['key_id'],
                    'key_preview': api_key_result.get('key_preview')
                },
                'next_steps': [
                    'Verify your email address',
                    'Read the integration documentation', 
                    'Make your first API call',
                    'Register your first product'
                ],
                'dashboard_url': f"/dashboard/manufacturer/{user_id}",
                'documentation_url': "/docs/getting-started",
                'integration_guides': {
                    'rest_api': "/docs/api/rest",
                    'webhooks': "/docs/api/webhooks",
                    'sdks': "/docs/sdks"
                }
            }
            
        except Exception as e:
            logger.error(f"Manufacturer registration error: {e}")
            return {
                'success': False,
                'error': 'Registration failed due to server error'
            }
    
    def _create_sandbox_api_key(self, user_id: ObjectId, company_name: str) -> Dict[str, Any]:
        """Create sandbox API key for new manufacturer"""
        try:
            # Generate API key
            api_key = f"sk_test_{secrets.token_urlsafe(32)}"
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Create API key record
            api_key_doc = {
                'manufacturer_id': user_id,
                'name': 'Sandbox API Key',
                'key_hash': key_hash,
                'key_prefix': api_key[:12] + '...',
                'environment': 'sandbox',
                'permissions': [
                    'verify_products',
                    'register_products',
                    'get_products',
                    'get_analytics'
                ],
                'rate_limits': {
                    'requests_per_minute': 60,
                    'requests_per_hour': 1000,
                    'requests_per_day': 1000,
                    'requests_per_month': 1000
                },
                'usage_stats': {
                    'total_requests': 0,
                    'requests_today': 0,
                    'requests_this_month': 0,
                    'last_used': None
                },
                'created_at': datetime.now(timezone.utc),
                'revoked': False,
                'is_sandbox': True
            }
            
            result = self.db.api_keys.insert_one(api_key_doc)
            
            return {
                'success': True,
                'api_key': api_key,
                'key_preview': api_key[:8],
                'key_id': str(result.inserted_id)
            }
            
        except Exception as e:
            logger.error(f"Error creating sandbox API key: {e}")
            return {
                'success': False,
                'error': 'Failed to create API key'
            }
  
    def verify_email(self, verification_token: str) -> Dict[str, Any]:
        """Verify manufacturer email address"""
        try:
            # Find verification token
            token_doc = self.db.verification_tokens.find_one({
                'token': verification_token,
                'type': 'email_verification',
                'used': False,
                'expires_at': {'$gte': datetime.now(timezone.utc)}
            })
            
            if not token_doc:
                return {
                    'success': False,
                    'error': 'Invalid or expired verification token'
                }
            
            user_id = token_doc['user_id']
            
            # Update user email verification
            update_result = self.db.users.update_one(
                {'_id': user_id},
                {
                    '$set': {
                        'email_verified': True,
                        'verification_status': 'verified',
                        'onboarding_steps.email_verified': True,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {
                    'success': False,
                    'error': 'Failed to verify email'
                }
            
            # Mark token as used
            self.db.verification_tokens.update_one(
                {'_id': token_doc['_id']},
                {'$set': {'used': True, 'used_at': datetime.now(timezone.utc)}}
            )
            
            # Create production API key for verified users
            try:
                production_key_result = self._create_production_api_key(user_id)
                production_access = production_key_result['success']
            except Exception as e:
                logger.warning(f"Failed to create production API key: {e}")
                production_access = False
            
            return {
                'success': True,
                'message': 'Email verified successfully',
                'user_id': str(user_id),
                'production_access': production_access
            }
            
        except Exception as e:
            logger.error(f"Email verification error: {e}")
            return {
                'success': False,
                'error': 'Email verification failed'
            }
    
    def _create_production_api_key(self, user_id: ObjectId) -> Dict[str, Any]:
        """Create production API key for verified manufacturers"""
        try:
            # Get manufacturer info
            manufacturer = self.db.users.find_one({'_id': user_id})
            if not manufacturer:
                return {'success': False, 'error': 'Manufacturer not found'}
            
            # Generate production API key
            api_key = f"sk_live_{secrets.token_urlsafe(32)}"
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Create production API key record
            api_key_doc = {
                'manufacturer_id': user_id,
                'name': 'Production API Key',
                'key_hash': key_hash,
                'key_prefix': api_key[:12] + '...',
                'environment': 'production',
                'permissions': [
                    'verify_products',
                    'register_products',
                    'get_products',
                    'get_analytics',
                    'webhooks'
                ],
                'rate_limits': {
                    'requests_per_minute': 100,
                    'requests_per_hour': 5000,
                    'requests_per_day': 50000,
                    'requests_per_month': 1000000
                },
                'usage_stats': {
                    'total_requests': 0,
                    'requests_today': 0,
                    'requests_this_month': 0,
                    'last_used': None
                },
                'created_at': datetime.now(timezone.utc),
                'revoked': False,
                'is_sandbox': False
            }
            
            result = self.db.api_keys.insert_one(api_key_doc)
            
            return {
                'success': True,
                'api_key': api_key,
                'key_preview': api_key[:8],
                'key_id': str(result.inserted_id)
            }
            
        except Exception as e:
            logger.error(f"Error creating production API key: {e}")
            return {
                'success': False,
                'error': 'Failed to create production API key'
            }
    
    def resend_verification_email(self, email: str) -> Dict[str, Any]:
        """Resend verification email"""
        try:
            email = email.lower().strip()
            
            # Find unverified manufacturer
            manufacturer = self.db.users.find_one({
                'primary_email': email,
                'role': 'manufacturer',
                'email_verified': False
            })
            
            if not manufacturer:
                return {
                    'success': False,
                    'error': 'No unverified account found with this email'
                }
            
            # Check if recent verification email was sent (rate limiting)
            recent_token = self.db.verification_tokens.find_one({
                'user_id': manufacturer['_id'],
                'type': 'email_verification',
                'created_at': {'$gte': datetime.now(timezone.utc) - timedelta(minutes=5)}
            })
            
            if recent_token:
                return {
                    'success': False,
                    'error': 'Verification email was sent recently. Please wait 5 minutes.'
                }
            
            # Generate new token
            verification_token = secrets.token_urlsafe(32)
            
            # Store new token
            token_doc = {
                'user_id': manufacturer['_id'],
                'token': verification_token,
                'type': 'email_verification',
                'email': email,
                'used': False,
                'created_at': datetime.now(timezone.utc),
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=24)
            }
            self.db.verification_tokens.insert_one(token_doc)
            
            # Send email
            result = notification_service.send_welcome_email(
                email,
                manufacturer.get('current_company_name', 'Your Company'),
                verification_token
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Resend verification error: {e}")
            return {
                'success': False,
                'error': 'Failed to resend verification email'
            }
    
    def get_onboarding_progress(self, user_id: str) -> Dict[str, Any]:
        """Get manufacturer's onboarding progress"""
        try:
            if not ObjectId.is_valid(user_id):
                return {'success': False, 'error': 'Invalid user ID'}
            
            manufacturer = self.db.users.find_one({
                '_id': ObjectId(user_id),
                'role': 'manufacturer'
            })
            
            if not manufacturer:
                return {'success': False, 'error': 'Manufacturer not found'}
            
            onboarding_steps = manufacturer.get('onboarding_steps', {})
            
            # Calculate completion percentage
            total_steps = len(onboarding_steps)
            completed_steps = sum(1 for completed in onboarding_steps.values() if completed)
            completion_percentage = (completed_steps / total_steps * 100) if total_steps > 0 else 0
            
            # Determine next step
            next_step = self._get_next_onboarding_step(onboarding_steps)
            
            # Get recommendations
            recommendations = self._get_onboarding_recommendations(onboarding_steps, manufacturer)
            
            return {
                'success': True,
                'progress': onboarding_steps,
                'completion_percentage': completion_percentage,
                'next_step': next_step,
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.error(f"Get onboarding progress error: {e}")
            return {
                'success': False,
                'error': 'Failed to get onboarding progress'
            }
    
    def _get_next_onboarding_step(self, steps: Dict[str, bool]) -> Optional[str]:
        """Determine the next onboarding step"""
        step_order = [
            'email_verified',
            'documentation_viewed',
            'first_api_call',
            'first_product_registered',
            'integration_completed'
        ]
        
        for step in step_order:
            if not steps.get(step, False):
                return step
        
        return None
    
    def _get_onboarding_recommendations(self, steps: Dict[str, bool], 
                                       manufacturer: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get personalized onboarding recommendations"""
        recommendations = []
        
        if not steps.get('email_verified', False):
            recommendations.append({
                'title': 'Verify Your Email',
                'description': 'Verify your email to unlock production API access',
                'action': 'Check your email for verification link',
                'priority': 'high'
            })
        
        if not steps.get('documentation_viewed', False):
            recommendations.append({
                'title': 'Read Documentation',
                'description': 'Learn how to integrate our verification API',
                'action': 'Visit /docs/getting-started',
                'priority': 'medium'
            })
        
        if not steps.get('first_api_call', False):
            recommendations.append({
                'title': 'Make Your First API Call',
                'description': 'Test the API with your sandbox key',
                'action': 'Try the verification endpoint',
                'priority': 'medium'
            })
        
        if not steps.get('first_product_registered', False):
            recommendations.append({
                'title': 'Register Your First Product',
                'description': 'Add a product to start offering verification',
                'action': 'Use the product registration API',
                'priority': 'high'
            })
        
        # Check trial expiry
        trial_expires = manufacturer.get('trial_expires')
        if trial_expires and isinstance(trial_expires, datetime):
            days_left = (trial_expires - datetime.now(timezone.utc)).days
            if days_left <= 3:
                recommendations.append({
                    'title': 'Upgrade Your Plan',
                    'description': f'Your trial expires in {days_left} days',
                    'action': 'Choose a paid plan to continue service',
                    'priority': 'urgent'
                })
        
        return recommendations
    
    def mark_onboarding_step_completed(self, user_id: str, step: str) -> Dict[str, Any]:
        """Mark an onboarding step as completed"""
        try:
            if not ObjectId.is_valid(user_id):
                return {'success': False, 'error': 'Invalid user ID'}
            
            valid_steps = [
                'email_verified',
                'first_api_call', 
                'first_product_registered',
                'integration_completed',
                'documentation_viewed'
            ]
            
            if step not in valid_steps:
                return {'success': False, 'error': 'Invalid onboarding step'}
            
            update_result = self.db.users.update_one(
                {'_id': ObjectId(user_id), 'role': 'manufacturer'},
                {
                    '$set': {
                        f'onboarding_steps.{step}': True,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            if update_result.modified_count == 0:
                return {'success': False, 'error': 'Failed to update onboarding step'}
            
            return {'success': True, 'message': f'Onboarding step "{step}" marked as completed'}
            
        except Exception as e:
            logger.error(f"Mark onboarding step error: {e}")
            return {
                'success': False,
                'error': 'Failed to mark onboarding step as completed'
            }


onboarding_service = OnboardingService()