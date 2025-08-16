from .auth import auth_bp
from .manufacturer import manufacturer_bp
from .developer import developer_bp
from .verification import verification_bp
from .utility import utility_bp

def register_blueprints(app):
    """Register all blueprints with the Flask app"""
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(manufacturer_bp, url_prefix='/manufacturer')
    app.register_blueprint(developer_bp, url_prefix='/developer')
    app.register_blueprint(verification_bp, url_prefix='/')
    app.register_blueprint(utility_bp, url_prefix='/')

__all__ = ['register_blueprints']