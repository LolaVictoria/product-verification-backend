from flask import Blueprint

def register_all_routes(app):
    """Register all route blueprints with the Flask app"""
    try:
        from .auth_routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
    except ImportError:
        print("Warning: auth_routes not found, creating placeholder...")
        auth_bp = Blueprint('auth', __name__)
        @auth_bp.route('/health')
        def auth_health():
            return {'status': 'Auth routes not implemented yet'}
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
   
    try:
        from .manufacturer_routes import manufacturer_bp
        app.register_blueprint(manufacturer_bp, url_prefix='/api/manufacturers')
    except ImportError:
        print("Warning: manufacturer_routes not found, creating placeholder...")
        manufacturer_bp = Blueprint('manufacturers', __name__)
        @manufacturer_bp.route('/health')
        def manufacturer_health():
            return {'status': 'Manufacturer routes not implemented yet'}
        app.register_blueprint(manufacturer_bp, url_prefix='/api/manufacturers')
   
    try:
        from .product_routes import product_bp
        app.register_blueprint(product_bp, url_prefix='/api/products')
    except ImportError:
        print("Warning: product_routes not found, creating placeholder...")
        product_bp = Blueprint('products', __name__)
        @product_bp.route('/health')
        def product_health():
            return {'status': 'Product routes not implemented yet'}
        app.register_blueprint(product_bp, url_prefix='/api/products')
   
    try:
        from .verification_routes import create_verification_routes
        verification_bp = create_verification_routes(app)
        app.register_blueprint(verification_bp, url_prefix='/api/verification')
    except ImportError:
        print("Warning: verification_routes not found, creating placeholder...")
        verification_bp = Blueprint('verification', __name__)
        @verification_bp.route('/health')
        def verification_health():
            return {'status': 'Verification routes not implemented yet'}
        app.register_blueprint(verification_bp, url_prefix='/api/verification')
   
    try:
        from .integration_routes import integration_bp
        app.register_blueprint(integration_bp, url_prefix='/api/integration')
    except ImportError:
        print("Warning: integration_routes not found, creating placeholder...")
        integration_bp = Blueprint('integration', __name__)
        @integration_bp.route('/health')
        def integration_health():
            return {'status': 'Integration routes not implemented yet'}
        app.register_blueprint(integration_bp, url_prefix='/api/integration')
   
    @app.route('/api/health')
    def main_health():
        return {
            'status': 'OK',
            'message': 'Product Verification API is running',
            'version': '1.0.0'
        }
   
    print("All available routes registered successfully!")