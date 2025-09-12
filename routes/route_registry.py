from flask import Blueprint

def register_all_routes(app):
    """Register all route blueprints with the Flask app"""
    
    # Auth routes
    try:
        from routes.auth_routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
        print("✓ Auth routes registered successfully")
    except ImportError as e:
        print(f"Warning: auth_routes not found ({e}), creating placeholder...")
        auth_bp = Blueprint('auth', __name__)
        @auth_bp.route('/health')
        def auth_health():
            return {'status': 'Auth routes not implemented yet'}
        app.register_blueprint(auth_bp, url_prefix='/auth')
   
    # Manufacturer routes
    try:
        from routes.manufacturer_routes import manufacturer_bp
        app.register_blueprint(manufacturer_bp, url_prefix='/manufacturer')
        print("✓ Manufacturer routes registered successfully")
    except ImportError as e:
        print(f"Warning: manufacturer_routes not found ({e}), creating placeholder...")
        manufacturer_bp = Blueprint('manufacturer', __name__)
        @manufacturer_bp.route('/health')
        def manufacturer_health():
            return {'status': 'Manufacturer routes not implemented yet'}
        app.register_blueprint(manufacturer_bp, url_prefix='/manufacturer')
   
    # Analytics routes
    try:
        from routes.analytics_routes import analytics_bp
        app.register_blueprint(analytics_bp, url_prefix='/analytics')
        print("✓ Analytics routes registered successfully")
    except ImportError as e:
        print(f"Warning: analytics_routes not found ({e}), creating placeholder...")
        analytics_bp = Blueprint('analytics', __name__)
        @analytics_bp.route('/health')
        def analytics_health():
            return {'status': 'Analytics routes not implemented yet'}
        app.register_blueprint(analytics_bp, url_prefix='/analytics')
    
    # Product routes
    try:
        from routes.product_routes import product_bp
        app.register_blueprint(product_bp, url_prefix='/products')
        print("✓ Product routes registered successfully")
    except ImportError as e:
        print(f"Warning: product_routes not found ({e}), creating placeholder...")
        product_bp = Blueprint('product', __name__)
        @product_bp.route('/health')
        def product_health():
            return {'status': 'Product routes not implemented yet'}
        app.register_blueprint(product_bp, url_prefix='/products')

    # Verification routes
    try:
        from routes.verification_routes import create_verification_routes
        verification_bp = create_verification_routes(app)
        app.register_blueprint(verification_bp, url_prefix='/verification')
        print("✓ Verification routes registered successfully")
    except ImportError as e:
        print(f"Warning: verification_routes not found ({e}), creating placeholder...")
        verification_bp = Blueprint('verification', __name__)
        @verification_bp.route('/health')
        def verification_health():
            return {'status': 'Verification routes not implemented yet'}
        app.register_blueprint(verification_bp, url_prefix='/verification')
   
    # Integration routes
    try:
        from routes.integration_routes import integration_bp
        app.register_blueprint(integration_bp, url_prefix='/integration')
        print("✓ Integration routes registered successfully")
    except ImportError as e:
        print(f"Warning: integration_routes not found ({e}), creating placeholder...")
        integration_bp = Blueprint('integration', __name__)
        @integration_bp.route('/health')
        def integration_health():
            return {'status': 'Integration routes not implemented yet'}
        app.register_blueprint(integration_bp, url_prefix='/integration')
   
    # Main health check
    @app.route('/health')
    def main_health():
        return {
            'status': 'OK',
            'message': 'Product Verification API is running',
            'version': '1.0.0'
        }
   
    print("All available routes registered successfully!")