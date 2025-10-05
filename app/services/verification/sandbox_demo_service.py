# services/demo_service.py
from datetime  import datetime, timezone,  timedelta
import logging
import random
logger = logging.getLogger(__name__)
class SandboxDemoService:
    # Add these methods to your existing DemoService
    @staticmethod
    def simulate_verification(self, serial_number: str, demo_products: list, company_name: str) -> dict:
        """Simulate product verification for demo"""
        # Find matching demo product
        product = next((p for p in demo_products if p['serial_number'] == serial_number), None)
        
        if product:
            # Return realistic verification response
            return {
                'authentic': product['authentic'],
                'serial_number': serial_number,
                'brand': product['brand'],
                'model': product['model'],
                'device_type': product['device_type'],
                'manufacturer_name': company_name,
                'source': 'demo_blockchain' if product['authentic'] else 'demo_database',
                'blockchain_verified': product['authentic'],
                'confidence_score': 95.5 if product['authentic'] else 15.2,
                'verification_timestamp': datetime.now(timezone.utc).isoformat(),
                'message': 'Product verified successfully' if product['authentic'] else 'Counterfeit product detected'
            }
        else:
            # Product not found
            return {
                'authentic': False,
                'serial_number': serial_number,
                'message': 'Product not found in database',
                'source': 'not_found',
                'confidence_score': 0,
                'verification_timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    @staticmethod
    def generate_demo_analytics(self, company_name: str, requests_made: int) -> dict:
        """Generate realistic demo analytics"""
        # Simulate realistic analytics data
        base_date = datetime.now(timezone.utc) - timedelta(days=30)
        
        daily_verifications = []
        for i in range(30):
            date = base_date + timedelta(days=i)
            # Add some randomness but trending upward
            count = random.randint(50, 200) + (i * 2)  # Growing trend
            daily_verifications.append({
                'date': date.strftime('%Y-%m-%d'),
                'verifications': count,
                'authentic': int(count * 0.85),  # 85% authentic rate
                'counterfeit': int(count * 0.15)
            })
        
        return {
            'demo_mode': True,
            'company_name': company_name,
            'time_range': 'last_30_days',
            'summary': {
                'total_verifications': sum(d['verifications'] for d in daily_verifications),
                'authentic_rate': 85.3,
                'counterfeit_detections': sum(d['counterfeit'] for d in daily_verifications),
                'demo_requests_made': requests_made
            },
            'daily_verifications': daily_verifications,
            'top_verified_products': [
                {'model': 'Pro-X1', 'verifications': 1250},
                {'model': 'Ultra-M2', 'verifications': 890},
                {'model': 'Watch-S1', 'verifications': 650}
            ],
            'counterfeit_alerts': [
                {
                    'date': (datetime.now(timezone.utc) - timedelta(days=2)).strftime('%Y-%m-%d'),
                    'product': 'Fake Pro-X1 Copy',
                    'location': 'Online Marketplace',
                    'severity': 'High'
                }
            ],
            'note': 'This is demo data. Real analytics will show your actual verification patterns.'
        }
    
    @staticmethod
    def track_demo_conversion_interest(self, email: str, company: str, ip_address: str):
        """Track when demo users show interest in upgrading"""
        try:
            conversion_data = {
                'email': email,
                'company': company,
                'ip_address': ip_address,
                'interested_at': datetime.now(timezone.utc),
                'source': 'demo_upgrade_prompt',
                'follow_up_needed': True
            }
            
            # Store for sales team follow-up
            self.db.demo_conversions.insert_one(conversion_data)
            
            # Could trigger email to sales team
            # notification_service.notify_sales_team_demo_interest(conversion_data)
            
        except Exception as e:
            logger.error(f"Failed to track demo conversion interest: {e}")

# Frontend integration example for the sandbox
# This would go in your frontend code:
"""
// JavaScript example for integrating the demo
class ProductVerifyDemo {
    constructor() {
        this.demoSession = null;
        this.apiBaseUrl = '/api/v1/demo';
    }
    
    async startDemo(companyName, email) {
        const response = await fetch(`${this.apiBaseUrl}/start-session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ company_name: companyName, email })
        });
        
        const data = await response.json();
        if (data.success) {
            this.demoSession = data.demo_session;
            this.showDemoInterface();
        }
        return data;
    }
    
    async verifyProduct(serialNumber) {
        if (!this.demoSession) {
            throw new Error('Demo session not started');
        }
        
        const response = await fetch(`${this.apiBaseUrl}/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Demo-Session': this.demoSession.session_id
            },
            body: JSON.stringify({
                serial_number: serialNumber,
                customer_email: 'demo@customer.com'
            })
        });
        
        return await response.json();
    }
    
    showDemoInterface() {
        // Update UI to show:
        // - Demo API key (masked)
        // - Sample products to test
        // - Live verification results
        // - Real-time analytics
        // - Upgrade prompts when limits approached
    }
}
"""

demo_service = SandboxDemoService()