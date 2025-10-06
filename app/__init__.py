# app.py 
from flask import Flask, jsonify
from flask_cors import CORS
import logging
import os
import traceback
import sys
from datetime import datetime
from app.config.environment import config

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    try:
        from app.config.environment import config
        app_config = config.get_config()
        app.config.update(app_config)
        app.logger.info("Configuration loaded successfully")
    except Exception as e:
        app.logger.error(f"Configuration failed: {e}")
        # Fallback to basic config
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
        app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret')
        app.config['MONGODB_URI'] = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/product_verification')
    
    allowed_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
    
    CORS(app, 
         origins=allowed_origins,
         allow_headers=['Content-Type', 'Authorization', 'X-API-Key'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         supports_credentials=True)
   
    # Initialize database with error handling
    try:
        from app.config.database import get_db_connection
        from app.utils.database_helpers import init_database_indexes
        get_db_connection()
        init_database_indexes()
        app.logger.info("Database connection established")
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
        print(f"Database error: {e}")
    
    # Initialize blockchain service with error handling
    try:
        from app.services.blockchain_service import blockchain_service
        app.logger.info("Blockchain service loaded")
    except Exception as e:
        app.logger.error(f"Blockchain service failed: {e}")
        print(f"Blockchain service error: {e}")
    
    # Register routes using the route registry
    try:
        from app.api.route_registry import register_routes
        register_routes(app)
        app.logger.info("Routes registered successfully")
    except Exception as e:
        app.logger.error(f"Route registration failed: {e}")
        print(f"Route registration failed: {e}")
        traceback.print_exc()
    
    # Add essential endpoints
    register_essential_endpoints(app)
    
    # Error handlers
    register_error_handlers(app)
    
    # Print route info for debugging
    print_route_info(app)
    
    return app


def register_essential_endpoints(app):
    """Register essential endpoints that always work"""
    
    @app.route('/')
    def home():
        return {
            "message": "Product Authentication API",
            "status": "running",
            "version": "1.0",
            "debug_endpoints": {
                "health_check": "/health",
                "test_db": "/test-db",
                "debug_imports": "/debug/imports"
            }
        }

    @app.route('/health')
    def health():
        """Simple health check"""
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        overall_healthy = True
        
        # Database check
        try:
            from app.config.database import get_db_connection
            db = get_db_connection()
            db.admin.command('ping')
            health_data['checks']['database'] = {'status': 'healthy'}
        except Exception as e:
            health_data['checks']['database'] = {'status': 'unhealthy', 'error': str(e)}
            overall_healthy = False
        
        # Environment check
        required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            health_data['checks']['environment'] = {
                'status': 'unhealthy', 
                'missing_vars': missing_vars
            }
            overall_healthy = False
        else:
            health_data['checks']['environment'] = {'status': 'healthy'}
        
        health_data['status'] = 'healthy' if overall_healthy else 'unhealthy'
        return jsonify(health_data), 200 if overall_healthy else 503

    @app.route('/test-db')
    def test_db():
        """Test database connection"""
        try:
            from app.config.database import get_db_connection
            db = get_db_connection()
            collections = db.list_collection_names()
            return {
                'database': 'connected',
                'collections': collections,
                'collection_count': len(collections)
            }
        except Exception as e:
            return {
                'database': 'failed',
                'error': str(e)
            }, 500

    @app.route('/debug/imports')
    def debug_imports():
        """Debug import issues"""
        import_results = {}
        
        modules_to_test = [
            'app.config.database',
            'app.config.environment',
            'app.services.blockchain_service',
            'app.api.route_registry',
            'app.api.v1.auth_routes',
            'app.api.v1.demo_routes',
            'app.api.v1.manufacturer.dashboard_routes',
            'app.api.v1.manufacturer.product_routes',
        ]
        
        for module_name in modules_to_test:
            try:
                __import__(module_name)
                import_results[module_name] = 'success'
            except Exception as e:
                import_results[module_name] = f'failed: {str(e)}'
        
        return {
            'import_test_results': import_results,
            'python_path': sys.path,
            'current_directory': os.getcwd()
        }


def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized'}), 401
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500


def setup_logging(app):
    """Setup application logging"""
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Quiet down noisy loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)


def print_route_info(app):
    """Print registered routes for debugging"""
    print("\n" + "="*60)
    print("REGISTERED ROUTES:")
    print("="*60)
    
    route_count = len(list(app.url_map.iter_rules()))
    if route_count <= 5:
        print("⚠️  WARNING: Very few routes registered!")
        print("This suggests route registration failed.")
    else:
        print(f"✓ {route_count} routes registered successfully")
    
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods - {'HEAD', 'OPTIONS'})
        print(f"{rule.rule:40} -> {rule.endpoint:30} [{methods}]")
    print("="*60 + "\n")


if __name__ == '__main__':
    try:
        app = create_app()
        print("✅ Application created successfully")
    except Exception as e:
        print(f"❌ Application creation failed: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print("\n" + "="*80)
    print("PRODUCT AUTHENTICATION API - STARTING")
    print("="*80)
    print(f"Server starting on: http://0.0.0.0:{port}")
    print(f"Debug mode: {debug}")
    print(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    print("\nESSENTIAL ENDPOINTS:")
    print("- http://localhost:5000/health (Health Check)")
    print("- http://localhost:5000/test-db (Database Test)")
    print("- http://localhost:5000/debug/imports (Import Debug)")
    print("="*80 + "\n")
    
    # try:
    #     app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
    # except Exception as e:
    #     print(f"\n❌ CRITICAL ERROR: Failed to start server")
    #     print(f"Error: {e}")
    #     traceback.print_exc()
    #     sys.exit(1)