"""
API Route Registry
Central registration of all API routes
"""
import logging
from flask import Flask

logger = logging.getLogger(__name__)


def register_routes(app: Flask):
    """Register all API routes with the Flask app"""
    
    try:
        # ===============================
        # V1 API ROUTES
        # ===============================
        
        # Auth Routes
        from app.api.v1.auth_routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/v1/auth')
        logger.info("Registered: /v1/auth")
        
        # Demo Routes 
        try:
            from app.api.v1.demo_routes import demo_bp
            app.register_blueprint(demo_bp, url_prefix='/v1/demo')
            logger.info("Registered: /v1/demo")
        except ImportError:
            logger.warning("demo_routes.py not found - skipping demo routes")
        # ===============================
        # MANUFACTURER ROUTES
        # ===============================
        from app.api.v1.manufacturer.dashboard_routes import dashboard_bp
        from app.api.v1.manufacturer.product_routes import product_bp
        from app.api.v1.manufacturer.api_key_routes import api_key_bp
        from app.api.v1.manufacturer.analytics_routes import analytics_bp
        from app.api.v1.manufacturer.onboarding_routes import onboarding_bp;
        
        
        app.register_blueprint(dashboard_bp, url_prefix='/v1/manufacturer/dashboard')
        app.register_blueprint(product_bp, url_prefix='/v1/manufacturer/products')
        app.register_blueprint(api_key_bp, url_prefix='/v1/manufacturer-keys')
        app.register_blueprint(analytics_bp, url_prefix='/v1/manufacturer/analytics')
        app.register_blueprint(onboarding_bp, url_prefix='/v1/manufacturer/onboarding')
        
        
        logger.info("Registered: /v1/manufacturer/* (5 blueprints)")
        
        # ===============================
        # ADMIN ROUTES
        # ===============================
        from app.api.v1.admin.manufacturer_management_routes import admin_manufacturer_bp
        from app.api.v1.admin.system_routes import system_bp
        from app.api.v1.admin.audit_routes import audit_bp
        
        app.register_blueprint(admin_manufacturer_bp, url_prefix='/v1/admin')
        app.register_blueprint(system_bp, url_prefix='/v1/admin/system')
        app.register_blueprint(audit_bp, url_prefix='/v1/admin/audit')
        
        logger.info("Registered: /v1/admin/* (3 blueprints)")
        
        # ===============================
        # BILLING ROUTES
        # ===============================
        from app.api.v1.billing.subscription_routes import subscription_bp
        from app.api.v1.billing.webhook_routes import billing_webhook_bp
        
        app.register_blueprint(subscription_bp, url_prefix='/v1/billing/subscription')
        app.register_blueprint(billing_webhook_bp, url_prefix='/v1/billing/webhooks')
        
        logger.info("Registered: /v1/billing/* (2 blueprints)")
        
        # ===============================
        # VERIFICATION ROUTES
        # ===============================
        from app.api.v1.verification.public_routes import public_verification_bp
        from app.api.v1.verification.reporting_routes import reporting_bp
        
        app.register_blueprint(public_verification_bp, url_prefix='/v1/verification')
        app.register_blueprint(reporting_bp, url_prefix='/v1/verification')
        
        logger.info("Registered: /v1/verification/* (2 blueprints)")
        
        # ===============================
        # EXTERNAL API ROUTES (API Key Auth)
        # ===============================
        from app.api.external.verification_routes import verification_api_bp
        from app.api.external.crypto_routes import crypto_bp
        from app.api.external.webhook_routes import webhook_bp
        
        # Note: verification_api_bp already has url_prefix='/external'
        app.register_blueprint(verification_api_bp)
        app.register_blueprint(crypto_bp)
        app.register_blueprint(webhook_bp)
        
        logger.info("Registered: /external/* (3 blueprints)")
        
        # ===============================
        # HEALTH & STATUS ROUTES
        # ===============================
        @app.route('/health', methods=['GET'])
        def health_check():
            """Basic health check endpoint"""
            return {'status': 'healthy', 'service': 'product-verification-api'}, 200
        
        @app.route('/health', methods=['GET'])
        def api_health_check():
            """API health check with version info"""
            return {
                'status': 'healthy',
                'service': 'product-verification-api',
                'version': '1.0.0',
                'api_version': 'v1'
            }, 200
        
        logger.info("Registered: Health check endpoints")
        
        # ===============================
        # ROUTE SUMMARY
        # ===============================
        logger.info("=" * 60)
        logger.info("ROUTE REGISTRATION SUMMARY")
        logger.info("=" * 60)
        logger.info("Auth Routes:          /v1/auth/*")
        logger.info("Manufacturer Routes:  /v1/manufacturer/* (4 blueprints)")
        logger.info("Admin Routes:         /v1/admin/* (3 blueprints)")
        logger.info("Billing Routes:       /v1/billing/* (2 blueprints)")
        logger.info("Verification Routes:  /v1/verification/* (2 blueprints)")
        logger.info("External API:         /external/* (3 blueprints)")
        logger.info("Health Checks:        /health, /health")
        logger.info("=" * 60)
        logger.info(f"Total Blueprints Registered: 15")
        logger.info("=" * 60)
        
        return True
        
    except ImportError as e:
        logger.error(f"Failed to import route module: {e}")
        logger.error("Please ensure all route files exist and have correct imports")
        raise
    
    except Exception as e:
        logger.error(f"Route registration failed: {e}")
        raise


def list_routes(app: Flask):
    """List all registered routes (for debugging)"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return sorted(routes, key=lambda x: x['path'])


def print_routes(app: Flask):
    """Pretty print all registered routes"""
    routes = list_routes(app)
    
    print("\n" + "=" * 80)
    print("REGISTERED API ROUTES")
    print("=" * 80)
    
    current_prefix = None
    for route in routes:
        path = route['path']
        methods = ', '.join([m for m in route['methods'] if m not in ['HEAD', 'OPTIONS']])
        
        # Group by prefix
        prefix = '/'.join(path.split('/')[:4])
        if prefix != current_prefix:
            current_prefix = prefix
            print(f"\n{prefix}/*")
            print("-" * 80)
        
        print(f"  {methods:20} {path}")
    
    print("\n" + "=" * 80)
    print(f"Total Routes: {len(routes)}")
    print("=" * 80 + "\n")