# app.py - Main Flask Application Entry Point
from flask import Flask
from flask_cors import CORS
from config.settings import get_config
from config.__init__ import DatabaseConfig
from middleware.auth_middleware import AuthMiddleware
from middleware.logging_middleware import setup_logging
from routes.route_registry import register_all_routes
import os
from dotenv import load_dotenv
from routes.route_registry import register_all_routes
from routes.verification_routes import create_verification_routes
# Load environment variables
load_dotenv()

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    config = get_config()
    app.config.from_object(config)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-default-secret-key')
    app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/verification_system')

    # Register verification routes
    verification_bp = create_verification_routes(app)
    app.register_blueprint(verification_bp, url_prefix='/api/verification')
    # Initialize extensions
    AuthMiddleware.configure_cors(app)
    setup_logging()
    
    # Initialize database
    DatabaseConfig.init_db()
    
    # Register all routes
    register_all_routes(app)
    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        return {
            'status': 'healthy',
            'environment': config_name,
            'version': '1.0.0'
        }
    
    return app

# For development server
app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )