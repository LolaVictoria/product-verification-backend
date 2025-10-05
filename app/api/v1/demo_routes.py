# api/v1/demo.py 
"""
Interactive sandbox/demo platform for prospects to test the system
Like Stripe's demo but for product verification
"""
from flask import Blueprint, request, session
from datetime import datetime, timezone, timedelta
import secrets
from app.api.middleware.response_middleware import response_middleware
from app.services.verification.sandbox_demo_service import demo_service
from app.utils.generate_demo_data import generate_demo_data

demo_bp = Blueprint('demo', __name__, url_prefix='/api/v1/demo')

@demo_bp.route('/start-session', methods=['POST'])
def start_demo_session():
    """Start a new demo session for anonymous user"""
    try:
        data = request.get_json()
        
        # Generate demo session
        demo_session = {
            'session_id': secrets.token_urlsafe(16),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            'visitor_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'demo_company': data.get('company_name', f'Demo Corp {secrets.randbelow(999):03d}'),
            'demo_email': data.get('email', f'demo{secrets.randbelow(9999):04d}@example.com'),
            'demo_api_key': f'pk_demo_{secrets.token_urlsafe(32)}',
            'requests_made': 0,
            'max_requests': 50,  # Limit demo usage
            'demo_products': []
        }
        
        # Create sample products for demo
        sample_products = generate_demo_data.create_sample_products(demo_session['demo_company'])
        demo_session['demo_products'] = sample_products
        
        # Store session in Redis/memory (expires in 2 hours)
        session['demo_session'] = demo_session
        
        return response_middleware.create_cors_response({
            'success': True,
            'demo_session': demo_session,
            'getting_started': {
                'step_1': 'Use the demo API key to test verification',
                'step_2': 'Try verifying the sample products provided',
                'step_3': 'View real-time analytics',
                'step_4': 'Test webhook notifications'
            },
            'sample_api_call': {
                'method': 'POST',
                'url': '/api/v1/demo/verify',
                'headers': {
                    'X-Demo-Session': demo_session['session_id'],
                    'Content-Type': 'application/json'
                },
                'body': {
                    'serial_number': sample_products[0]['serial_number'] if sample_products else 'DEMO123456',
                    'customer_email': 'customer@example.com'
                }
            }
        }, 200)
        
    except Exception as e:
        return response_middleware.create_cors_response({
            'success': False,
            'error': 'Failed to start demo session'
        }, 500)

@demo_bp.route('/verify', methods=['POST'])
def demo_verify_product():
    """Demo product verification - simulates real API"""
    try:
        # Check demo session
        demo_session_id = request.headers.get('X-Demo-Session')
        if not demo_session_id or 'demo_session' not in session:
            return response_middleware.create_cors_response({
                'error': 'Demo session required. Start a session first.'
            }, 401)
        
        demo_session = session['demo_session']
        
        # Check session expiry
        expires_at = datetime.fromisoformat(demo_session['expires_at'])
        if datetime.now(timezone.utc) > expires_at:
            return response_middleware.create_cors_response({
                'error': 'Demo session expired. Please start a new session.'
            }, 401)
        
        # Check request limits
        if demo_session['requests_made'] >= demo_session['max_requests']:
            return response_middleware.create_cors_response({
                'error': f'Demo limit reached ({demo_session["max_requests"]} requests). Sign up for full access.'
            }, 429)
        
        data = request.get_json()
        serial_number = data.get('serial_number')
        
        if not serial_number:
            return response_middleware.create_cors_response({
                'error': 'serial_number is required'
            }, 400)
        
        # Simulate verification based on demo products
        verification_result = demo_service.simulate_verification(
            serial_number, 
            demo_session['demo_products'],
            demo_session['demo_company']
        )
        
        # Update session stats
        demo_session['requests_made'] += 1
        session['demo_session'] = demo_session
        
        # Add demo-specific metadata
        verification_result.update({
            'demo_mode': True,
            'requests_remaining': demo_session['max_requests'] - demo_session['requests_made'],
            'session_expires_in_minutes': int((expires_at - datetime.now(timezone.utc)).total_seconds() / 60)
        })
        
        return response_middleware.create_cors_response(verification_result, 200)
        
    except Exception as e:
        return response_middleware.create_cors_response({
            'error': 'Demo verification failed'
        }, 500)

@demo_bp.route('/analytics', methods=['GET'])
def demo_analytics():
    """Demo analytics dashboard"""
    try:
        demo_session_id = request.headers.get('X-Demo-Session')
        if not demo_session_id or 'demo_session' not in session:
            return response_middleware.create_cors_response({
                'error': 'Demo session required'
            }, 401)
        
        demo_session = session['demo_session']
        
        # Generate realistic demo analytics
        analytics_data = demo_service.generate_demo_analytics(
            demo_session['demo_company'],
            demo_session['requests_made']
        )
        
        return response_middleware.create_cors_response(analytics_data, 200)
        
    except Exception as e:
        return response_middleware.create_cors_response({
            'error': 'Demo analytics failed'
        }, 500)

@demo_bp.route('/upgrade-prompt', methods=['POST'])
def show_upgrade_prompt():
    """Show upgrade prompt when demo limits reached"""
    try:
        data = request.get_json()
        email = data.get('email', '')
        company = data.get('company', '')
        
        # Track conversion interest
        if email:
            demo_service.track_demo_conversion_interest(email, company, request.remote_addr)
        
        return response_middleware.create_cors_response({
            'success': True,
            'upgrade_options': {
                'trial': {
                    'name': '14-Day Free Trial',
                    'description': 'Full access with 1,000 API requests',
                    'price': 'Free',
                    'action': 'Start Free Trial'
                },
                'starter': {
                    'name': 'Starter Plan',
                    'description': '10,000 requests/month with analytics',
                    'price': '$99/month',
                    'action': 'Choose Starter'
                },
                'professional': {
                    'name': 'Professional Plan',
                    'description': '100,000 requests/month with priority support',
                    'price': '$299/month',
                    'action': 'Choose Professional'
                }
            },
            'demo_limitations': [
                'Limited to 50 verification requests',
                'Demo data only (not real products)',
                'Session expires in 2 hours',
                'No webhook functionality',
                'Limited analytics data'
            ]
        }, 200)
        
    except Exception as e:
        return response_middleware.create_cors_response({
            'error': 'Failed to load upgrade options'
        }, 500)
