"""
Verification Routes Module
"""
from .public_routes import public_verification_bp
from .reporting_routes import reporting_bp

__all__ = [
    'public_verification_bp',
    'reporting_bp'
]