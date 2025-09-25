from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import os
import traceback
import sys
from datetime import datetime
from config.settings import get_config
from utils.database import get_db_connection, init_database_indexes
from services.blockchain_service import blockchain_service
from werkzeug.security import generate_password_hash
from middleware.auth_middleware import auth_middleware
from middleware.logging_middleware import init_logging_middleware
from routes.route_registry import register_all_routes

logger = logging.getLogger(__name__)

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Setup logging
    setup_logging(app)
    
    # Setup CORS
    CORS(app, 
         origins=config.CORS_ORIGINS,
         allow_headers=['Content-Type', 'Authorization', 'X-API-Key'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         supports_credentials=True)
    
    # Initialize database
    try:
        get_db_connection()
        init_database_indexes()
        app.logger.info("Database connection established")
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
        # Don't raise here - let the app start but mark as unhealthy
    
    # Initialize services
    try:
        # Services are already initialized as singletons
        app.logger.info("Services initialized")
    except Exception as e:
        app.logger.error(f"Service initialization failed: {e}")
    
    # Initialize middleware
    init_logging_middleware(app)
    
    # Register blueprints
    try:
        register_all_routes(app)
        app.logger.info("Routes registered successfully")
    except Exception as e:
        app.logger.error(f"Route registration failed: {e}")
        print(f"CRITICAL: Route registration failed: {e}")
        traceback.print_exc()
    
    # Add debugging endpoints
    register_debug_endpoints(app)
    
    # Print all registered routes for debugging
    print("\n" + "="*60)
    print("REGISTERED ROUTES:")
    print("="*60)
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods - {'HEAD', 'OPTIONS'})
        print(f"{rule.rule:40} -> {rule.endpoint:30} [{methods}]")
    print("="*60 + "\n")

    # Error handlers
    register_error_handlers(app)
    
    # Test password hashing (remove in production)
    hashed_password = generate_password_hash("Damilola11264")
    print("Sample password hash:", hashed_password)
    
    return app

def register_debug_endpoints(app):
    """Register debugging and health check endpoints"""
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Comprehensive health check endpoint"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        overall_healthy = True
        
        # Database check
        try:
            db = get_db_connection()
            collections = db.list_collection_names()
            health_status['checks']['database'] = {
                'status': 'healthy',
                'collections_count': len(collections),
                'collections': collections[:5]  # Limit output
            }
        except Exception as e:
            health_status['checks']['database'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_healthy = False
        
        # Blockchain service check
        try:
            blockchain_connected = blockchain_service.is_connected()
            health_status['checks']['blockchain'] = {
                'status': 'healthy' if blockchain_connected else 'unhealthy',
                'connected': blockchain_connected
            }
        except Exception as e:
            health_status['checks']['blockchain'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
        
        # Environment variables check
        required_env_vars = ['JWT_SECRET_KEY', 'MONGO_URI', 'SECRET_KEY']
        env_status = {}
        for var in required_env_vars:
            env_status[var] = 'set' if os.getenv(var) else 'missing'
            if not os.getenv(var):
                overall_healthy = False
        
        health_status['checks']['environment'] = {
            'status': 'healthy' if all(os.getenv(var) for var in required_env_vars) else 'unhealthy',
            'variables': env_status
        }
        
        # Import checks
        import_status = {}
        critical_imports = [
            'utils.auth',
            'utils.database', 
            'routes.auth_routes',
            'services.auth_service'
        ]
        
        for module_name in critical_imports:
            try:
                __import__(module_name)
                import_status[module_name] = 'ok'
            except Exception as e:
                import_status[module_name] = f'failed: {str(e)}'
                overall_healthy = False
        
        health_status['checks']['imports'] = {
            'status': 'healthy' if all('ok' in status for status in import_status.values()) else 'unhealthy',
            'modules': import_status
        }
        
        health_status['status'] = 'healthy' if overall_healthy else 'unhealthy'
        
        return jsonify(health_status), 200 if overall_healthy else 503

    @app.route('/debug/auth', methods=['GET'])
    def debug_auth():
        """Debug authentication system"""
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'auth_debug': {}
        }
        
        try:
            # Test auth imports
            from utils.auth import authenticate_admin, authenticate_manufacturer, debug_user_collections
            debug_info['auth_debug']['imports'] = 'success'
            
            # Test database collections
            try:
                collections_info = debug_user_collections()
                debug_info['auth_debug']['collections'] = collections_info
            except Exception as e:
                debug_info['auth_debug']['collections'] = f'error: {str(e)}'
            
            # Test password functions
            try:
                from utils.auth import verify_password_bcrypt
                test_hash = generate_password_hash("test123")
                debug_info['auth_debug']['password_functions'] = {
                    'bcrypt_available': True,
                    'test_hash_generated': bool(test_hash)
                }
            except Exception as e:
                debug_info['auth_debug']['password_functions'] = f'error: {str(e)}'
                
        except Exception as e:
            debug_info['auth_debug']['imports'] = f'failed: {str(e)}'
            debug_info['auth_debug']['traceback'] = traceback.format_exc()
        
        return jsonify(debug_info)

    @app.route('/debug/routes', methods=['GET'])
    def debug_routes():
        """List all registered routes"""
        routes_info = {
            'timestamp': datetime.now().isoformat(),
            'total_routes': 0,
            'routes': []
        }
        
        for rule in app.url_map.iter_rules():
            methods = list(rule.methods - {'HEAD', 'OPTIONS'})
            routes_info['routes'].append({
                'rule': rule.rule,
                'endpoint': rule.endpoint,
                'methods': methods
            })
        
        routes_info['total_routes'] = len(routes_info['routes'])
        
        # Group by blueprint
        blueprint_routes = {}
        for route in routes_info['routes']:
            blueprint = route['endpoint'].split('.')[0] if '.' in route['endpoint'] else 'main'
            if blueprint not in blueprint_routes:
                blueprint_routes[blueprint] = []
            blueprint_routes[blueprint].append(route)
        
        routes_info['by_blueprint'] = blueprint_routes
        
        return jsonify(routes_info)

    @app.route('/debug/env', methods=['GET'])
    def debug_environment():
        """Debug environment variables (safe version)"""
        env_info = {
            'timestamp': datetime.now().isoformat(),
            'environment': {}
        }
        
        # Safe environment variables to show
        safe_vars = [
            'FLASK_ENV', 'FLASK_DEBUG', 'PORT', 'LOG_LEVEL',
            'CORS_ORIGINS', 'DATABASE_NAME'
        ]
        
        # Sensitive variables - only show if they exist (not values)
        sensitive_vars = [
            'JWT_SECRET_KEY', 'SECRET_KEY', 'MONGO_URI', 'DATABASE_URL'
        ]
        
        for var in safe_vars:
            env_info['environment'][var] = os.getenv(var, 'not_set')
        
        for var in sensitive_vars:
            env_info['environment'][var] = 'set' if os.getenv(var) else 'not_set'
        
        return jsonify(env_info)

    @app.route('/debug/test-auth', methods=['POST'])
    def test_auth_endpoint():
        """Test authentication with dummy data"""
        data = request.get_json() or {}
        test_email = data.get('email', 'test@example.com')
        test_password = data.get('password', 'test123')
        
        test_results = {
            'timestamp': datetime.now().isoformat(),
            'test_data': {
                'email': test_email,
                'password_provided': bool(test_password)
            },
            'results': {}
        }
        
        # Test admin authentication function
        try:
            from utils.auth import authenticate_admin
            test_results['results']['admin_function'] = 'imported_successfully'
        except Exception as e:
            test_results['results']['admin_function'] = f'import_failed: {str(e)}'
        
        # Test manufacturer authentication function
        try:
            from utils.auth import authenticate_manufacturer
            test_results['results']['manufacturer_function'] = 'imported_successfully'
        except Exception as e:
            test_results['results']['manufacturer_function'] = f'import_failed: {str(e)}'
        
        # Test auth service
        try:
            from services.auth_service import auth_service
            test_results['results']['auth_service'] = 'imported_successfully'
        except Exception as e:
            test_results['results']['auth_service'] = f'import_failed: {str(e)}'
        
        return jsonify(test_results)

    @app.route('/debug/fix-503', methods=['GET'])
    def fix_503_guide():
        """Provide 503 error fixing guide"""
        guide = {
            'timestamp': datetime.now().isoformat(),
            'message': '503 Service Unavailable - Troubleshooting Guide',
            'common_causes': [
                'Backend server not running',
                'Database connection failed',
                'Import errors in Python modules',
                'Missing environment variables',
                'Route registration failed'
            ],
            'quick_fixes': [
                '1. Check if MongoDB is running: systemctl status mongod',
                '2. Verify environment variables: check .env file',
                '3. Test imports: python -c "from utils.auth import authenticate_admin"',
                '4. Check database: python -c "from utils.database import get_db_connection; print(get_db_connection())"',
                '5. Restart server: python app.py'
            ],
            'endpoints_to_test': [
                'GET /health - Overall health check',
                'GET /debug/auth - Authentication system debug',
                'GET /debug/routes - List all routes',
                'POST /debug/test-auth - Test auth functions'
            ]
        }
        
        return jsonify(guide)

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return auth_middleware.create_error_response("Bad request", 400)
    
    @app.errorhandler(401)
    def unauthorized(error):
        return auth_middleware.create_error_response("Unauthorized", 401)
    
    @app.errorhandler(403)
    def forbidden(error):
        return auth_middleware.create_error_response("Forbidden", 403)
    
    @app.errorhandler(404)
    def not_found(error):
        return auth_middleware.create_error_response("Resource not found", 404)
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return auth_middleware.create_error_response("Rate limit exceeded", 429)
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return auth_middleware.create_error_response("Internal server error", 500)

def setup_logging(app):
    """Setup application logging"""
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(app.config.get('LOG_FILE', 'logs/app.log')),
            logging.StreamHandler()
        ]
    )
    
    # Set specific logger levels
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

# Create the application instance
app = create_app()

@app.route('/')
def home():
    return {
        "message": "Product Authentication API",
        "status": "running",
        "version": "1.0",
        "debug_endpoints": {
            "health_check": "/health",
            "auth_debug": "/debug/auth",
            "routes_list": "/debug/routes", 
            "environment": "/debug/env",
            "test_auth": "/debug/test-auth",
            "fix_503_guide": "/debug/fix-503"
        },
        "api_endpoints": {
            "crypto_manufacturer": "/api/manufacturers/create-crypto",
            "crypto_product": "/api/products/register-crypto",
            "verify_product": "/api/verify/crypto/<serial_number>",
            "manufacturer_profile": "/api/manufacturer/profile"
        }
    }

@app.route('/api')
def api_info():
    return {'message': 'Product Authentication API', 'status': 'active'}

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print("\n" + "="*80)
    print("PRODUCT AUTHENTICATION API - STARTING")
    print("="*80)
    print(f"Server starting on: http://0.0.0.0:{port}")
    print(f"Debug mode: {debug}")
    print(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    print("\nDEBUG ENDPOINTS:")
    print("- http://localhost:5000/health (Health Check)")
    print("- http://localhost:5000/debug/auth (Auth System Debug)")
    print("- http://localhost:5000/debug/routes (All Routes)")
    print("- http://localhost:5000/debug/fix-503 (503 Error Guide)")
    print("="*80 + "\n")
    
    try:
        app.run(
            host='0.0.0.0',
            port=port, 
            debug=debug, 
            threaded=True
        )
    except Exception as e:
        print(f"\nCRITICAL ERROR: Failed to start server")
        print(f"Error: {e}")
        traceback.print_exc()
        sys.exit(1)