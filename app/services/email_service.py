# services/email_service.py
import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)

class EmailService:
    """
    Cost-effective email service for B2B SaaS platform
    Starts with console/mock emails, upgrades to real service when revenue grows
    """
    
    def __init__(self):
        self.email_mode = os.getenv('EMAIL_MODE', 'console')  # console, mock, sendgrid, ses
        self.from_email = os.getenv('FROM_EMAIL', 'noreply@productverify.com')
        self.company_name = os.getenv('COMPANY_NAME', 'ProductVerify')
        self.frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        
        # Initialize real email service if configured
        if self.email_mode == 'sendgrid':
            self._init_sendgrid()
        elif self.email_mode == 'ses':
            self._init_ses()
    
    def _init_sendgrid(self):
        """Initialize SendGrid (when you have revenue)"""
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail
            
            self.sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
            if self.sendgrid_api_key:
                self.sg = sendgrid.SendGridAPIClient(api_key=self.sendgrid_api_key)
                logger.info("SendGrid initialized successfully")
            else:
                logger.warning("SendGrid API key not found, falling back to console mode")
                self.email_mode = 'console'
        except ImportError:
            logger.warning("SendGrid library not installed, falling back to console mode")
            self.email_mode = 'console'
    
    def _init_ses(self):
        """Initialize AWS SES (alternative to SendGrid)"""
        try:
            import boto3
            
            self.ses_client = boto3.client(
                'ses',
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
            )
            logger.info("AWS SES initialized successfully")
        except Exception as e:
            logger.warning(f"AWS SES initialization failed: {e}, falling back to console mode")
            self.email_mode = 'console'
    
    def send_trial_expiry_warning(self, email: str, company_name: str, days_remaining: int) -> Dict[str, Any]:
        """Send trial expiry warning email"""
        try:
            subject = f"Your {self.company_name} trial expires in {days_remaining} days"
            
            upgrade_link = f"{self.frontend_url}/dashboard/billing"
            
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Your trial is expiring soon</h2>
                <p>Hi {company_name},</p>
                <p>Your {self.company_name} trial expires in <strong>{days_remaining} days</strong>.</p>
                <p>To continue using our product verification platform, please upgrade to a paid plan:</p>
                
                <div style="margin: 30px 0;">
                    <h3>What you'll lose without upgrading:</h3>
                    <ul>
                        <li>API access for product verification</li>
                        <li>Product registration capabilities</li>
                        <li>Analytics dashboard</li>
                        <li>Customer verification portal</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{upgrade_link}" 
                       style="background-color: #28a745; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 5px; font-weight: bold;">
                        Upgrade Now
                    </a>
                </div>
                
                <p>Questions? Reply to this email and we'll help you choose the right plan.</p>
                
                <p>Thanks,<br>
                The {self.company_name} Team</p>
            </div>
            """
            
            text_content = f"""
            Your trial is expiring soon
            
            Hi {company_name},
            
            Your {self.company_name} trial expires in {days_remaining} days.
            
            To continue using our product verification platform, please upgrade to a paid plan.
            
            What you'll lose without upgrading:
            • API access for product verification
            • Product registration capabilities
            • Analytics dashboard
            • Customer verification portal
            
            Upgrade now: {upgrade_link}
            
            Questions? Reply to this email and we'll help you choose the right plan.
            
            Thanks,
            The {self.company_name} Team
            """
            
            return self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                email_type='trial_expiry'
            )
            
        except Exception as e:
            logger.error(f"Send trial expiry warning error: {e}")
            return {
                'success': False,
                'error': 'Failed to send trial expiry warning'
            }
    
    def send_subscription_activated(self, email: str, company_name: str, plan: str) -> Dict[str, Any]:
        """Send subscription activation confirmation"""
        try:
            subject = f"Welcome to {self.company_name} {plan.title()} Plan!"
            
            dashboard_link = f"{self.frontend_url}/dashboard"
            
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>🎉 Your subscription is now active!</h2>
                <p>Hi {company_name},</p>
                <p>Congratulations! Your <strong>{plan.title()} Plan</strong> is now active.</p>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3>You now have access to:</h3>
                    <ul>
                        <li>Full API access with higher rate limits</li>
                        <li>Unlimited product registrations</li>
                        <li>Advanced analytics and reporting</li>
                        <li>Priority customer support</li>
                        <li>Production-ready integrations</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{dashboard_link}" 
                       style="background-color: #007bff; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 5px; font-weight: bold;">
                        Go to Dashboard
                    </a>
                </div>
                
                <p>Need help getting started? Check out our <a href="{self.frontend_url}/docs">documentation</a> 
                   or reply to this email.</p>
                
                <p>Thanks for choosing {self.company_name}!</p>
                <p>The {self.company_name} Team</p>
            </div>
            """
            
            text_content = f"""
            Your subscription is now active!
            
            Hi {company_name},
            
            Congratulations! Your {plan.title()} Plan is now active.
            
            You now have access to:
            • Full API access with higher rate limits
            • Unlimited product registrations  
            • Advanced analytics and reporting
            • Priority customer support
            • Production-ready integrations
            
            Go to Dashboard: {dashboard_link}
            
            Need help getting started? Check out our documentation at {self.frontend_url}/docs
            or reply to this email.
            
            Thanks for choosing {self.company_name}!
            The {self.company_name} Team
            """
            
            return self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                email_type='subscription_activated'
            )
            
        except Exception as e:
            logger.error(f"Send subscription activated error: {e}")
            return {
                'success': False,
                'error': 'Failed to send subscription activation email'
            }
    
    def _send_email(self, to_email: str, subject: str, html_content: str, text_content: str, email_type: str) -> Dict[str, Any]:
        """Send email using configured method"""
        try:
            if self.email_mode == 'console':
                return self._send_console_email(to_email, subject, html_content, text_content, email_type)
            elif self.email_mode == 'mock':
                return self._send_mock_email(to_email, subject, html_content, text_content, email_type)
            elif self.email_mode == 'sendgrid':
                return self._send_sendgrid_email(to_email, subject, html_content, text_content)
            elif self.email_mode == 'ses':
                return self._send_ses_email(to_email, subject, html_content, text_content)
            else:
                logger.warning(f"Unknown email mode: {self.email_mode}, falling back to console")
                return self._send_console_email(to_email, subject, html_content, text_content, email_type)
        
        except Exception as e:
            logger.error(f"Send email error: {e}")
            return {
                'success': False,
                'error': 'Failed to send email'
            }
    
    def _send_console_email(self, to_email: str, subject: str, html_content: str, text_content: str, email_type: str) -> Dict[str, Any]:
        """Console email mode - prints email to console (free for development)"""
        print("\n" + "="*80)
        print(f"📧 EMAIL ({email_type.upper()})")
        print("="*80)
        print(f"From: {self.from_email}")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(f"Type: {email_type}")
        print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        print("-"*80)
        print("TEXT CONTENT:")
        print(text_content)
        print("-"*80)
        print("HTML CONTENT:")
        print(html_content[:500] + "..." if len(html_content) > 500 else html_content)
        print("="*80 + "\n")
        
        return {
            'success': True,
            'message': 'Email logged to console',
            'email_id': f'console_{datetime.now().timestamp()}'
        }
    
    def _send_mock_email(self, to_email: str, subject: str, html_content: str, text_content: str, email_type: str) -> Dict[str, Any]:
        """Mock email mode - stores email in database (free for development)"""
        try:
            from app.config.database import get_db_connection
            db = get_db_connection()
            
            email_doc = {
                'from_email': self.from_email,
                'to_email': to_email,
                'subject': subject,
                'html_content': html_content,
                'text_content': text_content,
                'email_type': email_type,
                'status': 'sent',
                'sent_at': datetime.now(timezone.utc),
                'provider': 'mock'
            }
            
            result = db.email_logs.insert_one(email_doc)
            
            logger.info(f"Mock email sent to {to_email}: {subject}")
            
            return {
                'success': True,
                'message': 'Mock email stored in database',
                'email_id': str(result.inserted_id)
            }
            
        except Exception as e:
            logger.error(f"Mock email error: {e}")
            return {
                'success': False,
                'error': 'Failed to store mock email'
            }
    
    def _send_sendgrid_email(self, to_email: str, subject: str, html_content: str, text_content: str) -> Dict[str, Any]:
        """SendGrid email mode (paid service)"""
        try:
            from sendgrid.helpers.mail import Mail, Email, To, Content
            
            from_email = Email(self.from_email)
            to_email_obj = To(to_email)
            
            mail = Mail(
                from_email=from_email,
                to_emails=to_email_obj,
                subject=subject,
                html_content=Content("text/html", html_content),
                plain_text_content=Content("text/plain", text_content)
            )
            
            response = self.sg.send(mail)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"SendGrid email sent to {to_email}: {subject}")
                return {
                    'success': True,
                    'message': 'Email sent via SendGrid',
                    'email_id': response.headers.get('X-Message-Id', 'unknown')
                }
            else:
                logger.error(f"SendGrid error: {response.status_code} - {response.body}")
                return {
                    'success': False,
                    'error': f'SendGrid API error: {response.status_code}'
                }
                
        except Exception as e:
            logger.error(f"SendGrid email error: {e}")
            return {
                'success': False,
                'error': 'Failed to send email via SendGrid'
            }
    
    def _send_ses_email(self, to_email: str, subject: str, html_content: str, text_content: str) -> Dict[str, Any]:
        """AWS SES email mode (paid service)"""
        try:
            response = self.ses_client.send_email(
                Source=self.from_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {
                        'Text': {'Data': text_content, 'Charset': 'UTF-8'},
                        'Html': {'Data': html_content, 'Charset': 'UTF-8'}
                    }
                }
            )
            
            logger.info(f"SES email sent to {to_email}: {subject}")
            
            return {
                'success': True,
                'message': 'Email sent via AWS SES',
                'email_id': response['MessageId']
            }
            
        except Exception as e:
            logger.error(f"SES email error: {e}")
            return {
                'success': False,
                'error': 'Failed to send email via AWS SES'
            }
    
    def _get_welcome_email_html(self, company_name: str, verification_link: str) -> str:
        """Get welcome email HTML template"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #333; margin: 0;">{self.company_name}</h1>
                <p style="color: #666; margin: 5px 0 0 0;">Product Verification Platform</p>
            </div>
            
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
                <h2 style="margin: 0 0 10px 0;">Welcome to {self.company_name}!</h2>
                <p style="margin: 0; opacity: 0.9;">Your product verification platform is ready</p>
            </div>
            
            <div style="margin-bottom: 30px;">
                <p>Hi {company_name},</p>
                <p>Congratulations on creating your {self.company_name} account! You now have access to our 
                   powerful product verification platform.</p>
                
                <p><strong>🎉 Your 14-day trial includes:</strong></p>
                <ul style="line-height: 1.6;">
                    <li>1,000 API requests for product verification</li>
                    <li>100 product registrations</li>
                    <li>Sandbox API key (already generated)</li>
                    <li>Analytics dashboard</li>
                    <li>Email support</li>
                </ul>
            </div>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 30px 0;">
                <h3 style="margin: 0 0 15px 0; color: #333;">⚠️ First Step: Verify Your Email</h3>
                <p style="margin: 0 0 20px 0;">Please verify your email address to unlock production API access:</p>
                <div style="text-align: center;">
                    <a href="{verification_link}" 
                       style="background-color: #28a745; color: white; padding: 15px 30px; 
                              text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                        Verify Email Address
                    </a>
                </div>
            </div>
            
            <div style="margin: 30px 0;">
                <h3>🚀 Next Steps:</h3>
                <ol style="line-height: 1.8;">
                    <li><strong>Verify your email</strong> (click button above)</li>
                    <li><strong>Read our documentation</strong> - <a href="{self.frontend_url}/docs">Getting Started Guide</a></li>
                    <li><strong>Test the API</strong> with your sandbox key</li>
                    <li><strong>Register your first product</strong></li>
                    <li><strong>Integrate with your website</strong></li>
                </ol>
            </div>
            
            <div style="background: #e9ecef; padding: 20px; border-radius: 8px; margin: 30px 0;">
                <h4 style="margin: 0 0 10px 0;">📚 Helpful Resources:</h4>
                <p style="margin: 5px 0;"><a href="{self.frontend_url}/docs/api">API Documentation</a></p>
                <p style="margin: 5px 0;"><a href="{self.frontend_url}/docs/integration">Integration Examples</a></p>
                <p style="margin: 5px 0;"><a href="{self.frontend_url}/docs/sdks">SDK Downloads</a></p>
                <p style="margin: 5px 0;"><a href="{self.frontend_url}/support">Support Center</a></p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{self.frontend_url}/dashboard" 
                   style="background-color: #007bff; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 5px; font-weight: bold;">
                    Go to Dashboard
                </a>
            </div>
            
            <div style="border-top: 1px solid #eee; margin-top: 40px; padding-top: 20px; text-align: center; color: #666;">
                <p>Questions? Just reply to this email and we'll help you get started.</p>
                <p>The {self.company_name} Team</p>
                <p style="font-size: 12px; margin-top: 20px;">
                    This link expires in 24 hours. If you didn't create this account, you can safely ignore this email.
                </p>
            </div>
        </div>
        """
    
    def _get_welcome_email_text(self, company_name: str, verification_link: str) -> str:
        """Get welcome email text template"""
        return f"""
Welcome to {self.company_name}!

Hi {company_name},

Congratulations on creating your {self.company_name} account! You now have access to our powerful product verification platform.

🎉 Your 14-day trial includes:
• 1,000 API requests for product verification
• 100 product registrations  
• Sandbox API key (already generated)
• Analytics dashboard
• Email support

⚠️ FIRST STEP: Verify Your Email
Please verify your email address to unlock production API access:
{verification_link}

🚀 Next Steps:
1. Verify your email (click link above)
2. Read our documentation: {self.frontend_url}/docs
3. Test the API with your sandbox key
4. Register your first product
5. Integrate with your website

📚 Helpful Resources:
• API Documentation: {self.frontend_url}/docs/api
• Integration Examples: {self.frontend_url}/docs/integration  
• SDK Downloads: {self.frontend_url}/docs/sdks
• Support Center: {self.frontend_url}/support

Dashboard: {self.frontend_url}/dashboard

Questions? Just reply to this email and we'll help you get started.

The {self.company_name} Team

---
This link expires in 24 hours. If you didn't create this account, you can safely ignore this email.
        """
    
    def get_email_logs(self, user_id: str, limit: int = 50) -> Dict[str, Any]:
        """Get email logs for a user (when using mock mode)"""
        try:
            if self.email_mode != 'mock':
                return {
                    'success': False,
                    'error': 'Email logs only available in mock mode'
                }
            
            from app.config.database import get_db_connection
            db = get_db_connection()
            
            # Get user email
            from bson import ObjectId
            user = db.users.find_one({'_id': ObjectId(user_id)})
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            user_email = user.get('primary_email')
            
            # Get email logs
            emails = list(db.email_logs.find(
                {'to_email': user_email}
            ).sort('sent_at', -1).limit(limit))
            
            # Format emails
            for email in emails:
                email['_id'] = str(email['_id'])
                if 'sent_at' in email:
                    email['sent_at'] = email['sent_at'].isoformat()
            
            return {
                'success': True,
                'emails': emails,
                'total': len(emails)
            }
            
        except Exception as e:
            logger.error(f"Get email logs error: {e}")
            return {
                'success': False,
                'error': 'Failed to get email logs'
            }


# Singleton instance
email_service = EmailService()