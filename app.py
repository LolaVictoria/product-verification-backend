import os
import json
from flask import Flask, jsonify
from config import config
from extensions import mongo, jwt, cors, init_database, test_db_connection
from routes import register_blueprints
from services import BlockchainService, DatabaseService
from utils.helpers import JSONEncoder, setup_logging
import logging

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, that's okay

# Global blockchain service instance
blockchain_service = None

def create_app(config_name=None):
    """Application factory pattern"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'default')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Set custom JSON encoder
    app.json_encoder = JSONEncoder
    
    # Initialize extensions (REMOVED mongo.init_app - now handled in init_database)
    jwt.init_app(app)
    cors.init_app(app)
    
    # Setup logging
    setup_logging(app)
    
    # Test database connection first
    print("Testing database connection...")
    if not test_db_connection():
        print("Warning: Database connection test failed")
    
    # Initialize database with Flask app (this handles mongo.init_app and index creation)
    if init_database(app):
        print("Database initialization successful")
    else:
        print("Warning: Database initialization failed")
    
    # Initialize services
    global blockchain_service
    try:
        blockchain_service = BlockchainService(
            app.config['WEB3_PROVIDER'],
            app.config['CONTRACT_ADDRESS'],
            app.config['CONTRACT_ABI_PATH']
        )
        app.logger.info("Blockchain service initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize blockchain service: {e}")
        blockchain_service = None
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register JWT callbacks
    register_jwt_callbacks(app)
    
    # REMOVED: Old database index creation - now handled in init_database()
    # with app.app_context():
    #     try:
    #         DatabaseService.create_indexes()
    #         app.logger.info("Database indexes created/verified")
    #     except Exception as e:
    #         app.logger.error(f"Failed to create database indexes: {e}")
    
    return app

def register_error_handlers(app):
    """Register application error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed'}), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.'
        }), 429

def register_jwt_callbacks(app):
    """Register JWT-related callbacks"""
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has expired',
            'message': 'Please login again to get a new token'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'Invalid token',
            'message': 'Token signature verification failed'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'Authorization token required',
            'message': 'Request does not contain an access token'
        }), 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Fresh token required',
            'message': 'Please login again to continue'
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has been revoked',
            'message': 'Please login again'
        }), 401

# Create application instance
app = create_app()

@app.before_request
def before_request():
    """Run before the first request"""
    app.logger.info("Product Authentication API started successfully")
    
    # Log configuration (non-sensitive info only)
    app.logger.info(f"Environment: {os.getenv('FLASK_ENV', 'production')}")
    app.logger.info(f"Debug mode: {app.debug}")
    
    # Test services
    if blockchain_service:
        if blockchain_service.is_connected():
            app.logger.info("Blockchain connection: OK")
        else:
            app.logger.warning("Blockchain connection: FAILED")
    
    if DatabaseService.test_connection():
        app.logger.info("Database connection: OK")
    else:
        app.logger.warning("Database connection: FAILED")

@app.route('/')
def index():
    """API root endpoint"""
    return jsonify({
        'message': 'Product Authentication API',
        'version': '1.0.0',
        'status': 'active',
        'endpoints': {
            'authentication': '/auth/',
            'manufacturers': '/manufacturer/',
            'developers': '/developer/',
            'verification': '/verify/',
            'health_check': '/health',
            'statistics': '/stats',
            'documentation': 'https://docs.productauth.example.com'
        }
    })

if __name__ == '__main__':
    # Only for development - use a proper WSGI server in production
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
    )