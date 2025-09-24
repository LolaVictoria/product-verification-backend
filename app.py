# # app.py - Main Flask Application Entry Point
# from flask import Flask
# from flask_cors import CORS
# from config.settings import get_config
# from config.__init__ import DatabaseConfig
# from middleware.logging_middleware import setup_logging
# from routes.route_registry import register_all_routes
# import os
# from dotenv import load_dotenv

# load_dotenv()

# def create_app(config_name=None):
#     """Application factory pattern"""
#     app = Flask(__name__)
     
#     # Load configuration
#     config_name = config_name or os.getenv('FLASK_ENV', 'development')
#     config = get_config()
#     app.config.from_object(config)
#     app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-default-secret-key')
#     app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/verification_system')

#     # Configure CORS
#     CORS(app, 
#          origins=['http://localhost:3000', 'http://localhost:5173', 'https://blockchain-verification-esup.vercel.app'],
#          allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'Accept', 'Origin', 'Cache-Control', 'Pragma'],
#          methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
#          supports_credentials=True,
#          max_age=86400
#     )

   

#     # Initialize extensions
#     setup_logging()
    
#     # Initialize database
#     DatabaseConfig.init_db()
    
#     # Register all routes
#     register_all_routes(app)
    
#     # Health check endpoint
#     @app.route('/health', methods=['GET'])
#     def health_check():
#         return {
#             'status': 'healthy',
#             'environment': config_name,
#             'version': '1.0.0'
#         }
    
#     return app

# # For development server
# app = create_app()

# if __name__ == '__main__':
#     port = int(os.getenv('PORT', 5000))
#     debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
#     app.run(
#         host='0.0.0.0',
#         port=port,
#         debug=debug
#     )
from flask import Flask
from flask_cors import CORS
import logging
import os
from config.settings import get_config
from utils.database import get_db_connection, init_database_indexes
from services.blockchain_service import blockchain_service
from werkzeug.security import generate_password_hash
from middleware.auth_middleware import auth_middleware
from middleware.logging_middleware import init_logging_middleware
from routes.route_registry import register_all_routes
import logging 


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
        raise
    
    # Initialize services
    try:
        # Services are already initialized as singletons
        app.logger.info("Services initialized")
    except Exception as e:
        app.logger.error(f"Service initialization failed: {e}")
        raise
    
    # Initialize middleware
    init_logging_middleware(app)
    
    # Register blueprints
    register_all_routes(app)
    # Add this to see all routes
    for rule in app.url_map.iter_rules():
       print(f"{rule.rule} -> {rule.endpoint}")

    # Error handlers
    register_error_handlers(app)
    hashed_password = generate_password_hash("Damilola11264")
    print("this is it:", hashed_password)

    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return {
            'status': 'healthy',
            'database': 'connected' if get_db_connection() else 'disconnected',
            'blockchain': 'connected' if blockchain_service.is_connected() else 'disconnected'
        }
    
    return app
    

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
        "endpoints": {
            "health": "/api",
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
    
    print(f"Starting server on http://0.0.0.0:{port}")
    
    app.run(
        host='0.0.0.0',
        port=port, 
        debug=debug, 
        threaded=True
    ) 