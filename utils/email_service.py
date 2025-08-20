import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Email service for sending verification and other emails"""
    
    @staticmethod
    def _get_smtp_config():
        """Get SMTP configuration from environment variables"""
        return {
            'host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', 587)),
            'username': os.getenv('SMTP_USERNAME'),
            'password': os.getenv('SMTP_PASSWORD'),
            'from_email': os.getenv('FROM_EMAIL'),
            'from_name': os.getenv('FROM_NAME', 'Your App Name')
        }
    
    @staticmethod
    def _send_email(to_email, subject, html_content, text_content=None):
        """Send email using SMTP"""
        try:
            config = EmailService._get_smtp_config()
            
            if not all([config['username'], config['password'], config['from_email']]):
                logger.error("SMTP configuration is incomplete")
                raise Exception("Email configuration is incomplete")
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{config['from_name']} <{config['from_email']}>"
            msg['To'] = to_email
            
            # Create text and HTML parts
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            server = smtplib.SMTP(config['host'], config['port'])
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            raise e
    
    @staticmethod
    def send_verification_email(email, username, verification_token):
        """Send email verification email"""
        try:
            # Get base URL from environment or use default
            base_url = os.getenv('BASE_URL', 'http://localhost:5000')
            verification_link = f"{base_url}/auth/verify-email/{verification_token}"
            
            subject = "Verify Your Email Address"
            
            # HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background: #4CAF50;
                        color: white;
                        padding: 20px;
                        text-align: center;
                        border-radius: 5px 5px 0 0;
                    }}
                    .content {{
                        background: #f9f9f9;
                        padding: 30px;
                        border-radius: 0 0 5px 5px;
                    }}
                    .button {{
                        display: inline-block;
                        background: #4CAF50;
                        color: white;
                        padding: 12px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .footer {{
                        text-align: center;
                        color: #666;
                        font-size: 12px;
                        margin-top: 30px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Welcome to Our Platform!</h1>
                </div>
                <div class="content">
                    <h2>Hi {username},</h2>
                    <p>Thank you for creating an account with us! To complete your registration and start using all our features, please verify your email address.</p>
                    
                    <div style="text-align: center;">
                        <a href="{verification_link}" class="button">Verify Email Address</a>
                    </div>
                    
                    <p>If the button above doesn't work, you can also copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #4CAF50;">{verification_link}</p>
                    
                    <p><strong>Important:</strong></p>
                    <ul>
                        <li>This verification link will expire in 24 hours</li>
                        <li>You won't be able to log in until your email is verified</li>
                        <li>If you didn't create this account, please ignore this email</li>
                    </ul>
                    
                    <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                    
                    <p>Best regards,<br>The Team</p>
                </div>
                <div class="footer">
                    <p>This email was sent to {email}. If you didn't request this, please ignore this email.</p>
                </div>
            </body>
            </html>
            """
            
            # Plain text content (fallback)
            text_content = f"""
            Hi {username},
            
            Welcome to our platform! Please verify your email address by visiting this link:
            {verification_link}
            
            This link will expire in 24 hours.
            
            If you didn't create this account, please ignore this email.
            
            Best regards,
            The Team
            """
            
            EmailService._send_email(email, subject, html_content, text_content)
            logger.info(f"Verification email sent to {email}")
            
        except Exception as e:
            logger.error(f"Failed to send verification email to {email}: {str(e)}")
            raise e
    
    @staticmethod
    def send_welcome_email(email, username):
        """Send welcome email after verification"""
        try:
            subject = "Welcome! Your Account is Now Active"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome!</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background: #4CAF50;
                        color: white;
                        padding: 20px;
                        text-align: center;
                        border-radius: 5px 5px 0 0;
                    }}
                    .content {{
                        background: #f9f9f9;
                        padding: 30px;
                        border-radius: 0 0 5px 5px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🎉 Account Verified Successfully!</h1>
                </div>
                <div class="content">
                    <h2>Hi {username},</h2>
                    <p>Congratulations! Your email has been verified and your account is now fully active.</p>
                    
                    <p>You can now:</p>
                    <ul>
                        <li>Log in to your account</li>
                        <li>Access all platform features</li>
                        <li>Start exploring our services</li>
                    </ul>
                    
                    <p>Thank you for joining our platform. We're excited to have you on board!</p>
                    
                    <p>Best regards,<br>The Team</p>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            Hi {username},
            
            Congratulations! Your email has been verified and your account is now fully active.
            
            You can now log in and access all platform features.
            
            Thank you for joining our platform!
            
            Best regards,
            The Team
            """
            
            EmailService._send_email(email, subject, html_content, text_content)
            logger.info(f"Welcome email sent to {email}")
            
        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {str(e)}")
            # Don't raise exception for welcome email as it's not critical