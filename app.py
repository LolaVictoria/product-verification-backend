# app.py - Main Flask Application Entry Point
from flask import Flask
from flask_cors import CORS
from config.settings import get_config
from config.__init__ import DatabaseConfig
from middleware.logging_middleware import setup_logging
from routes.route_registry import register_all_routes
import os
from dotenv import load_dotenv
from routes.auth_routes import auth_bp

load_dotenv()

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    print("JWT_SECRET_KEY:", os.getenv('JWT_SECRET_KEY')) 
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    config = get_config()
    app.config.from_object(config)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-default-secret-key')
    app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/verification_system')

    # Configure CORS
    CORS(app, 
         origins=['http://localhost:3000', 'http://localhost:5173', 'https://blockchain-verification-esup.vercel.app'],
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'Accept', 'Origin', 'Cache-Control', 'Pragma'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
         supports_credentials=True,
         max_age=86400
    )

   

    # Initialize extensions
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