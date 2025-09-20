
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from typing import Dict, Optional
import threading
from jinja2 import Template

class EmailService:
    def __init__(self, config):
        self.config = config
        self.smtp_server = config.EMAIL_HOST
        self.smtp_port = config.EMAIL_PORT
        self.username = config.EMAIL_USERNAME
        self.password = config.EMAIL_PASSWORD
        self.use_tls = config.EMAIL_USE_TLS
    
    def _send_email(self, to_email: str, subject: str, body: str, is_html: bool = True):
        """Send email using SMTP"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html' if is_html else 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            return False
    
    def send_transfer_initiation_email(self, to_email: str, product_details: Dict, 
                                     transfer_id: str, execution_time: datetime):
        """Send email when transfer is initiated"""
        template = """
        <html>
        <body>
            <h2>Product Ownership Transfer Initiated</h2>
            <p>Dear User,</p>
            <p>A transfer has been initiated for your product:</p>
            <ul>
                <li><strong>Product:</strong> {{product_name}}</li>
                <li><strong>Serial Number:</strong> {{serial_number}}</li>
                <li><strong>Transfer ID:</strong> {{transfer_id}}</li>
                <li><strong>Execution Time:</strong> {{execution_time}}</li>
            </ul>
            <p>The transfer will complete automatically in 24 hours unless cancelled.</p>
            <p><a href="{{cancel_link}}">Cancel Transfer</a></p>
            <p>If you did not initiate this transfer, please cancel immediately.</p>
        </body>
        </html>
        """
        
        cancel_link = f"https://yourapp.com/cancel-transfer/{transfer_id}"
        
        html_content = Template(template).render(
            product_name=product_details.get('product_name'),
            serial_number=product_details.get('serial_number'),
            transfer_id=transfer_id,
            execution_time=execution_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            cancel_link=cancel_link
        )
        
        # Send in background thread
        threading.Thread(
            target=self._send_email,
            args=(to_email, "Product Transfer Initiated - Action Required", html_content)
        ).start()
    
    def send_transfer_warning_email(self, to_email: str, product_details: Dict, 
                                  transfer_id: str, hours_remaining: int):
        """Send warning email before transfer execution"""
        template = """
        <html>
        <body>
            <h2>Product Transfer Warning - {{hours}} Hours Remaining</h2>
            <p>Dear User,</p>
            <p>Your product transfer will complete in {{hours}} hours:</p>
            <ul>
                <li><strong>Product:</strong> {{product_name}}</li>
                <li><strong>Serial Number:</strong> {{serial_number}}</li>
                <li><strong>Transfer ID:</strong> {{transfer_id}}</li>
            </ul>
            <p><strong>This is your final warning!</strong></p>
            <p><a href="{{cancel_link}}">Cancel Transfer Now</a></p>
            <p>If you did not authorize this transfer, cancel immediately.</p>
        </body>
        </html>
        """
        
        cancel_link = f"https://yourapp.com/cancel-transfer/{transfer_id}"
        
        html_content = Template(template).render(
            hours=hours_remaining,
            product_name=product_details.get('product_name'),
            serial_number=product_details.get('serial_number'),
            transfer_id=transfer_id,
            cancel_link=cancel_link
        )
        
        threading.Thread(
            target=self._send_email,
            args=(to_email, f"URGENT: Transfer Completing in {hours_remaining} Hours", html_content)
        ).start()
    
    def send_transfer_completion_email(self, to_email: str, product_details: Dict, 
                                     transfer_id: str, success: bool):
        """Send email when transfer completes or fails"""
        if success:
            subject = "Product Transfer Completed Successfully"
            template = """
            <html>
            <body>
                <h2>Product Transfer Completed</h2>
                <p>Dear User,</p>
                <p>Your product transfer has been completed successfully:</p>
                <ul>
                    <li><strong>Product:</strong> {{product_name}}</li>
                    <li><strong>Serial Number:</strong> {{serial_number}}</li>
                    <li><strong>Transfer ID:</strong> {{transfer_id}}</li>
                    <li><strong>Completed At:</strong> {{timestamp}}</li>
                </ul>
                <p>The product ownership has been successfully transferred.</p>
            </body>
            </html>
            """
        else:
            subject = "Product Transfer Failed"
            template = """
            <html>
            <body>
                <h2>Product Transfer Failed</h2>
                <p>Dear User,</p>
                <p>Your product transfer could not be completed:</p>
                <ul>
                    <li><strong>Product:</strong> {{product_name}}</li>
                    <li><strong>Serial Number:</strong> {{serial_number}}</li>
                    <li><strong>Transfer ID:</strong> {{transfer_id}}</li>
                </ul>
                <p>Please contact support for assistance.</p>
            </body>
            </html>
            """
        
        html_content = Template(template).render(
            product_name=product_details.get('product_name'),
            serial_number=product_details.get('serial_number'),
            transfer_id=transfer_id,
            timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        )
        
        threading.Thread(
            target=self._send_email,
            args=(to_email, subject, html_content)
        ).start()
    
    def send_duress_alert_email(self, admin_email: str, transfer_details: Dict, 
                              user_details: Dict):
        """Send silent alert to security team for duress detection"""
        template = """
        <html>
        <body>
            <h2>SECURITY ALERT: Duress Transfer Detected</h2>
            <p>A transfer has been flagged as potentially initiated under duress:</p>
            <ul>
                <li><strong>Transfer ID:</strong> {{transfer_id}}</li>
                <li><strong>Product:</strong> {{product_name}}</li>
                <li><strong>Serial Number:</strong> {{serial_number}}</li>
                <li><strong>User Email:</strong> {{user_email}}</li>
                <li><strong>IP Address:</strong> {{ip_address}}</li>
                <li><strong>Location:</strong> {{location}}</li>
                <li><strong>Device:</strong> {{device_info}}</li>
                <li><strong>Detected At:</strong> {{timestamp}}</li>
            </ul>
            <p><strong>Actions Taken:</strong></p>
            <ul>
                <li>Transfer flagged for automatic cancellation</li>
                <li>User location tracking enabled</li>
                <li>Session recording started</li>
                <li>Law enforcement notification prepared</li>
            </ul>
        </body>
        </html>
        """
        
        html_content = Template(template).render(**transfer_details, **user_details)
        
        threading.Thread(
            target=self._send_email,
            args=(admin_email, "CRITICAL: Duress Transfer Detection", html_content)
        ).start()
