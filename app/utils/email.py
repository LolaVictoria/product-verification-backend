#utils/email.py
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)
def send_welcome_email(self, email: str, company_name: str, verification_token: str) -> Dict[str, Any]:
        """Send welcome email with verification link - ENHANCED VERSION"""
        try:
            verification_link = f"{self.frontend_url}/verify-email?token={verification_token}"
            subject = f"Welcome to {self.company_name}! Verify your email"
            
            # Enhanced HTML template with better verification flow
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #333; margin: 0;">{self.company_name}</h1>
                    <p style="color: #666; margin: 5px 0 0 0;">Product Verification Platform</p>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 30px 0;">
                    <h2 style="margin: 0 0 15px 0; color: #333;">⚠️ Action Required: Verify Your Email</h2>
                    <p style="margin: 0 0 20px 0;"><strong>Your account is almost ready!</strong></p>
                    <p>Click the button below to verify your email and unlock your API access:</p>
                    
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
                        <li>🔓 <strong>Production API access unlocked</strong></li>
                        <li>📊 <strong>Analytics dashboard enabled</strong></li>
                        <li>🔗 <strong>Integration guides available</strong></li>
                        <li>🎯 <strong>Full platform features</strong></li>
                    </ul>
                </div>
                
                <div style="border-top: 1px solid #eee; margin-top: 40px; padding-top: 20px; text-align: center; color: #666;">
                    <p>This verification link expires in 24 hours.</p>
                    <p>Need help? Reply to this email or visit our support center.</p>
                    <p>The {self.company_name} Team</p>
                </div>
            </div>
            """
            
            text_content = f"""
            Welcome to {self.company_name}!
            
            ACTION REQUIRED: Verify Your Email
            
            Your account is almost ready! Please verify your email address to unlock full access.
            
            Click here to verify: {verification_link}
            
            What happens after verification:
            - Production API access unlocked
            - Analytics dashboard enabled  
            - Integration guides available
            - Full platform features
            
            This link expires in 24 hours.
            
            The {self.company_name} Team
            """
            
            return self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
                email_type='welcome_verification'
            )
            
        except Exception as e:
            logger.error(f"Send welcome email error: {e}")
            return {
                'success': False,
                'error': 'Failed to send welcome email'
            }

        def send_email_verification(self, email: str, company_name: str, verification_token: str) -> Dict[str, Any]:
            """Send email verification (resend)"""
            try:
                verification_link = f"{self.frontend_url}/verify-email?token={verification_token}"
                
                subject = f"Verify your {self.company_name} email address"
                
                html_content = f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Verify Your Email Address</h2>
                    <p>Hi {company_name},</p>
                    <p>Please click the button below to verify your email address:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" 
                        style="background-color: #007bff; color: white; padding: 12px 24px; 
                                text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Verify Email Address
                        </a>
                    </div>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #666;">{verification_link}</p>
                    <p><small>This link expires in 24 hours.</small></p>
                </div>
                """
                
                text_content = f"""
                Verify Your Email Address
                
                Hi {company_name},
                
                Please verify your email address by clicking this link:
                {verification_link}
                
                This link expires in 24 hours.
                
                Thanks,
                The {self.company_name} Team
                """
                
                return self._send_email(
                    to_email=email,
                    subject=subject,
                    html_content=html_content,
                    text_content=text_content,
                    email_type='verification'
                )
                
            except Exception as e:
                logger.error(f"Send email verification error: {e}")
                return {
                    'success': False,
                    'error': 'Failed to send verification email'
                }

