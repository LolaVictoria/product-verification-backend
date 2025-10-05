# app/security/security_headers.py
from flask import request, g
import re

def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

def validate_request_size(max_size=10*1024*1024):  # 10MB default
    """Validate request size to prevent DoS"""
    if request.content_length and request.content_length > max_size:
        return {'error': 'Request too large'}, 413