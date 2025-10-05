#services/notification_service
import os
import smtplib
import requests
import logging
from bson import ObjectId
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
from app.config.database import get_db_connection

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self):
        self.db = get_db_connection()
        
        # Email configuration
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        
        # Webhook configuration
        self.webhook_timeout = int(os.getenv('WEBHOOK_TIMEOUT', '30'))
        self.webhook_retries = int(os.getenv('WEBHOOK_RETRIES', '3'))
    
    def send_email(self, to_email: str, subject: str, body: str, is_html: bool = True) -> bool:
        """Send email notification"""
        try:
            if not self.sender_email or not self.sender_password:
                logger.warning("Email credentials not configured")
                return False
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.sender_email
            msg['To'] = to_email
            
            # Add body
            if is_html:
                html_part = MIMEText(body, 'html')
                msg.attach(html_part)
            else:
                text_part = MIMEText(body, 'plain')
                msg.attach(text_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
        # ADD THESE METHODS TO YOUR EXISTING NotificationService CLASS:

    def send_welcome_email(self, email: str, company_name: str, verification_token: str) -> Dict[str, Any]:
        """Send welcome email with verification link"""
        try:
            frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
            verification_link = f"{frontend_url}/verify-email?token={verification_token}"
            
            subject = f"Welcome to Product Verification Platform - Verify Your Email"
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #28a745;">Welcome to Product Verification Platform!</h2>
                    
                    <p>Dear {company_name},</p>
                    
                    <p>Thank you for registering! Your account is almost ready.</p>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3>⚠️ Action Required: Verify Your Email</h3>
                        <p>Click the button below to verify your email and unlock production API access:</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{verification_link}"
                            style="background-color: #28a745; color: white; padding: 15px 30px;
                                    text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                                Verify Email & Activate Account
                            </a>
                        </div>
                        
                        <p style="font-size: 14px; color: #666;">
                            Can't click the button? Copy this link: {verification_link}
                        </p>
                    </div>
                    
                    <div style="margin: 30px 0;">
                        <h3>What happens after verification:</h3>
                        <ul style="line-height: 1.8;">
                            <li>🔓 Production API access unlocked</li>
                            <li>📊 Analytics dashboard enabled</li>
                            <li>🔗 Integration guides available</li>
                            <li>🎯 Full platform features</li>
                        </ul>
                    </div>
                    
                    <div style="border-top: 1px solid #eee; margin-top: 40px; padding-top: 20px; text-align: center; color: #666;">
                        <p>This verification link expires in 24 hours.</p>
                        <p>Need help? Reply to this email or visit our support center.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            success = self.send_email(email, subject, body, is_html=True)
            
            return {
                'success': success,
                'message': 'Welcome email sent' if success else 'Failed to send email'
            }
            
        except Exception as e:
            logger.error(f"Send welcome email error: {e}")
            return {
                'success': False,
                'error': 'Failed to send welcome email'
            }

    def send_duress_alert(self, contact_info: Dict, customer_id: str, location_data: Dict):
        """Send duress/emergency alert to emergency contact"""
        try:
            alert_message = f"""
            EMERGENCY ALERT - DURESS SITUATION DETECTED
            
            Customer ID: {customer_id}
            Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
            
            Location: {location_data.get('city', 'Unknown')}, {location_data.get('state', 'Unknown')}
            
            This is an automated alert from the Product Verification System.
            A duress PIN was used, indicating a potential emergency situation.
            
            If this is a false alarm, please contact support immediately.
            """
            
            if contact_info['type'] == 'email':
                self.send_email(
                    contact_info['value'], 
                    "EMERGENCY DURESS ALERT", 
                    alert_message,
                    is_html=False
                )
            # Add SMS implementation if needed
            
        except Exception as e:
            logger.error(f"Duress alert error: {e}")

    def send_counterfeit_email_alert(self, customer_id: str, product_data: Dict, 
                                    location_data: Dict, alert_id: str):
        """Send counterfeit detection email alert"""
        try:
            # Get customer email
            customer = self.db.users.find_one({'_id': ObjectId(customer_id)})
            if not customer:
                return
            
            email = customer.get('primary_email') or customer.get('email')
            if not email:
                return
            
            subject = "⚠️ Counterfeit Product Alert"
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #dc3545;">Counterfeit Product Detected</h2>
                    
                    <p>We detected a potential counterfeit product during verification.</p>
                    
                    <div style="background: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
                        <h3>Product Details:</h3>
                        <ul>
                            <li><strong>Serial Number:</strong> {product_data.get('serial_number', 'Unknown')}</li>
                            <li><strong>Product:</strong> {product_data.get('name', 'Unknown')}</li>
                            <li><strong>Detection Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</li>
                        </ul>
                    </div>
                    
                    <p><strong>What should you do?</strong></p>
                    <ol>
                        <li>Do not use the product</li>
                        <li>Report to the seller/retailer</li>
                        <li>Contact the manufacturer</li>
                        <li>Keep the product as evidence</li>
                    </ol>
                    
                    <p>Alert ID: {alert_id}</p>
                </div>
            </body>
            </html>
            """
            
            self.send_email(email, subject, body, is_html=True)
            
        except Exception as e:
            logger.error(f"Counterfeit email alert error: {e}")

    def send_counterfeit_sms_alert(self, customer_id: str, product_data: Dict, alert_id: str):
        """Send counterfeit SMS alert (stub - implement with Twilio/SNS)"""
        logger.info(f"SMS alert for customer {customer_id}: Counterfeit detected - Alert {alert_id}")
        # Implement with Twilio, AWS SNS, or other SMS service

    def send_counterfeit_push_notification(self, customer_id: str, product_data: Dict, alert_id: str):
        """Send counterfeit push notification (stub - implement with FCM/APNS)"""
        logger.info(f"Push notification for customer {customer_id}: Counterfeit detected - Alert {alert_id}")
        # Implement with Firebase Cloud Messaging or Apple Push Notification Service
    
    def send_webhook(self, webhook_url: str, payload: Dict[str, Any]) -> bool:
        """Send webhook notification with retries"""
        for attempt in range(self.webhook_retries):
            try:
                response = requests.post(
                    webhook_url,
                    json=payload,
                    timeout=self.webhook_timeout,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    logger.info(f"Webhook sent successfully to {webhook_url}")
                    return True
                else:
                    logger.warning(f"Webhook failed with status {response.status_code}: {response.text}")
                    
            except requests.RequestException as e:
                logger.warning(f"Webhook attempt {attempt + 1} failed: {e}")
                if attempt == self.webhook_retries - 1:
                    logger.error(f"All webhook attempts failed for {webhook_url}")
        
        return False
    
    def notify_verification_event(self, verification_data: Dict[str, Any]):
        """Send notifications for verification events"""
        try:
            # Get product and manufacturer details
            product = self.db.products.find_one({
                'serial_number': verification_data['serial_number']
            })
            
            if not product:
                return
            
            manufacturer = self.db.users.find_one({
                '_id': product['manufacturer_id']
            })
            
            if not manufacturer:
                return
            
            # Prepare notification payload
            payload = {
                'event_type': 'product_verification',
                'timestamp': verification_data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'product': {
                    'serial_number': verification_data['serial_number'],
                    'brand': product.get('brand'),
                    'model': product.get('model'),
                    'manufacturer': manufacturer.get('current_company_name')
                },
                'verification': {
                    'result': verification_data.get('result'),
                    'source': verification_data.get('source', 'database'),
                    'ip_address': verification_data.get('ip_address'),
                    'user_agent': verification_data.get('user_agent')
                }
            }
            
            # Send webhook if configured
            webhook_url = manufacturer.get('webhook_url')
            if webhook_url:
                self.send_webhook(webhook_url, payload)
            
            # Send email if enabled and result is concerning
            if (verification_data.get('result') == 'counterfeit' and 
                manufacturer.get('email_notifications', {}).get('counterfeit_alerts', False)):
                
                self.send_counterfeit_alert_email(
                    manufacturer.get('primary_email'),
                    payload
                )
            
        except Exception as e:
            logger.error(f"Error sending verification notifications: {e}")
    
    def process_webhook(self, data: Dict[str, Any], manufacturer_id: str, source_ip: str) -> Dict[str, Any]:
        """Process incoming webhook data"""
        try:
            webhook_entry = {
                'manufacturer_id': manufacturer_id,
                'source_ip': source_ip,
                'data': data,
                'timestamp': datetime.now(timezone.utc),
                'processed': True
            }
            
            result = self.db.webhook_logs.insert_one(webhook_entry)
            
            return {
                'webhook_id': str(result.inserted_id),
                'status': 'processed'
            }
            
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            return {
                'webhook_id': None,
                'status': 'failed',
                'error': str(e)
            }
    
    def send_counterfeit_alert_email(self, email: str, verification_data: Dict[str, Any]):
        """Send counterfeit detection alert email"""
        if not email:
            return
        
        subject = "Counterfeit Product Alert - Immediate Action Required"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #dc3545;">Counterfeit Product Detection Alert</h2>
                
                <p><strong>A counterfeit product has been detected in the system.</strong></p>
                
                <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
                    <h3>Product Details:</h3>
                    <ul>
                        <li><strong>Serial Number:</strong> {verification_data['product']['serial_number']}</li>
                        <li><strong>Brand:</strong> {verification_data['product']['brand']}</li>
                        <li><strong>Model:</strong> {verification_data['product']['model']}</li>
                        <li><strong>Manufacturer:</strong> {verification_data['product']['manufacturer']}</li>
                    </ul>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                    <h3>Verification Details:</h3>
                    <ul>
                        <li><strong>Detection Time:</strong> {verification_data['timestamp']}</li>
                        <li><strong>Source:</strong> {verification_data['verification']['source']}</li>
                        <li><strong>User IP:</strong> {verification_data['verification'].get('ip_address', 'Unknown')}</li>
                    </ul>
                </div>
                
                <div style="margin: 20px 0;">
                    <h3>Recommended Actions:</h3>
                    <ol>
                        <li>Investigate the source of this counterfeit product</li>
                        <li>Contact law enforcement if necessary</li>
                        <li>Review your distribution channels</li>
                        <li>Consider additional security measures</li>
                    </ol>
                </div>
                
                <p style="color: #6c757d; font-size: 12px; margin-top: 30px;">
                    This is an automated alert from the Product Verification System.
                    To modify your notification preferences, please contact support.
                </p>
            </div>
        </body>
        </html>
        """
        
        self.send_email(email, subject, body, is_html=True)
    
    def notify_manufacturer_verification(self, manufacturer_id: str, status: str):
        """Send notification when manufacturer verification status changes"""
        try:
            manufacturer = self.db.users.find_one({'_id': manufacturer_id})
            if not manufacturer:
                return
            
            email = manufacturer.get('primary_email')
            if not email:
                return
            
            if status == 'verified':
                subject = "Manufacturer Account Verified - Welcome to the Platform"
                body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #28a745;">Congratulations! Your Account Has Been Verified</h2>
                        
                        <p>Dear {manufacturer.get('current_company_name')},</p>
                        
                        <p>We're pleased to inform you that your manufacturer account has been successfully verified.</p>
                        
                        <div style="background: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin: 20px 0;">
                            <h3>What's Next?</h3>
                            <ul>
                                <li>Start registering your products</li>
                                <li>Generate API keys for integration</li>
                                <li>Configure webhook notifications</li>
                                <li>Access your analytics dashboard</li>
                            </ul>
                        </div>
                        
                        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                        
                        <p>Welcome aboard!</p>
                    </div>
                </body>
                </html>
                """
            else:
                subject = "Manufacturer Account Verification Update"
                body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2>Account Verification Update</h2>
                        
                        <p>Dear {manufacturer.get('current_company_name')},</p>
                        
                        <p>Your manufacturer account verification status has been updated to: <strong>{status}</strong></p>
                        
                        <p>If you have any questions about this update, please contact our support team.</p>
                    </div>
                </body>
                </html>
                """
            
            self.send_email(email, subject, body, is_html=True)
            
        except Exception as e:
            logger.error(f"Error sending manufacturer verification notification: {e}")
    
    def notify_api_key_created(self, manufacturer_id: str, api_key_name: str):
        """Send notification when new API key is created"""
        try:
            manufacturer = self.db.users.find_one({'_id': manufacturer_id})
            if not manufacturer:
                return
            
            email = manufacturer.get('primary_email')
            if not email:
                return
            
            subject = "New API Key Created"
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2>New API Key Created</h2>
                    
                    <p>Dear {manufacturer.get('current_company_name')},</p>
                    
                    <p>A new API key has been created for your account:</p>
                    
                    <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; margin: 20px 0;">
                        <ul>
                            <li><strong>Key Name:</strong> {api_key_name}</li>
                            <li><strong>Created:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                        </ul>
                    </div>
                    
                    <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                        <p><strong>Security Note:</strong> If you did not create this API key, please contact support immediately and revoke this key from your dashboard.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            self.send_email(email, subject, body, is_html=True)
            
        except Exception as e:
            logger.error(f"Error sending API key notification: {e}")
    
    def send_system_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None):
        """Send system-wide alerts to administrators"""
        try:
            # Get admin users
            admins = list(self.db.users.find({'role': 'admin'}))
            
            if not admins:
                logger.warning("No admin users found for system alert")
                return
            
            subject = f"System Alert: {alert_type}"
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #dc3545;">System Alert</h2>
                    
                    <div style="background: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
                        <h3>Alert Type: {alert_type}</h3>
                        <p>{message}</p>
                    </div>
                    
                    {f'<div style="background: #f8f9fa; padding: 15px; margin: 20px 0;"><h3>Details:</h3><pre>{details}</pre></div>' if details else ''}
                    
                    <p><strong>Timestamp:</strong> {datetime.now(timezone.utc).isoformat()}</p>
                    
                    <p>Please investigate this alert immediately.</p>
                </div>
            </body>
            </html>
            """
            
            for admin in admins:
                admin_email = admin.get('primary_email') or admin.get('email')
                if admin_email:
                    self.send_email(admin_email, subject, body, is_html=True)
            
        except Exception as e:
            logger.error(f"Error sending system alert: {e}")
    
    def log_notification(self, notification_type: str, recipient: str, 
                        status: str, details: Dict[str, Any] = None):
        """Log notification attempts for audit purposes"""
        try:
            log_entry = {
                'type': notification_type,
                'recipient': recipient,
                'status': status,
                'timestamp': datetime.now(timezone.utc),
                'details': details or {}
            }
            
            self.db.notification_logs.insert_one(log_entry)
            
        except Exception as e:
            logger.error(f"Error logging notification: {e}")


notification_service = NotificationService()