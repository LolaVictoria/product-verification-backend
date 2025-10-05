"""
Admin Routes Module
"""
from .manufacturer_management_routes import admin_manufacturer_bp
from .system_routes import system_bp
from .audit_routes import audit_bp

__all__ = [
    'admin_manufacturer_bp',
    'system_bp',
    'audit_bp'
]