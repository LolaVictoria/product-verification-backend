"""
Configuration module
Centralized configuration for database, external services, etc.
"""

from .database import get_db_connection, close_db_connection

__all__ = ['get_db_connection', 'close_db_connection']