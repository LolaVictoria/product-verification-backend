"""
Manufacturer Routes Module
"""
from .dashboard_routes import dashboard_bp
from .product_routes import product_bp
from .api_key_routes import api_key_bp
from .analytics_routes import analytics_bp
from .onboarding_routes import onboarding_bp
__all__ = [
    'dashboard_bp',
    'product_bp',
    'api_key_bp',
    'analytics_bp',
    'onboarding_bp'
]