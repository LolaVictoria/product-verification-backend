from flask import Blueprint, jsonify
from services import DatabaseService
from utils.helpers import create_error_response
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

utility_bp = Blueprint('utility', __name__)

@utility_bp.route('/health', methods=['GET'])
def health_check():
    """System health check endpoint"""
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {}
        }
        
        # Check database connection
        try:
            db_healthy = DatabaseService.test_connection()
            health_status['services']['database'] = {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'connected': db_healthy
            }
        except Exception as e:
            health_status['services']['database'] = {
                'status': 'unhealthy',
                'error': str(e),
                'connected': False
            }
        
        # Check blockchain connection
        try:
            from app import blockchain_service
            blockchain_connected = blockchain_service.is_connected()
            latest_block = blockchain_service.get_latest_block()
            
            health_status['services']['blockchain'] = {
                'status': 'healthy' if blockchain_connected else 'unhealthy',
                'connected': blockchain_connected,
                'latest_block': latest_block.number if latest_block else None
            }
        except Exception as e:
            health_status['services']['blockchain'] = {
                'status': 'unhealthy',
                'error': str(e),
                'connected': False
            }
        
        # Determine overall health
        all_healthy = all(
            service['status'] == 'healthy' 
            for service in health_status['services'].values()
        )
        
        if not all_healthy:
            health_status['status'] = 'degraded'
        
        status_code = 200 if all_healthy else 503
        return jsonify(health_status), status_code
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@utility_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get public system statistics"""
    try:
        stats = DatabaseService.get_system_stats()
        
        # Add some calculated metrics
        if stats:
            stats['timestamp'] = datetime.utcnow().isoformat()
            
            # Calculate growth rate if we have recent data
            if stats.get('recent_products_30d', 0) > 0:
                daily_avg = stats['recent_products_30d'] / 30
                stats['daily_average_new_products'] = round(daily_avg, 2)
        
        return jsonify(stats), 200
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return create_error_response('Internal server error', 500)

@utility_bp.route('/version', methods=['GET'])
def get_version():
    """Get API version information"""
    return jsonify({
        'version': '1.0.0',
        'api_name': 'Product Authentication API',
        'description': 'Blockchain-based product authentication system',
        'endpoints': {
            'auth': '/auth/*',
            'manufacturer': '/manufacturer/*',
            'developer': '/developer/*',
            'verification': '/verify/*',
            'utility': '/health, /stats, /version'
        },
        'documentation': 'https://docs.productauth.example.com',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@utility_bp.route('/system-info', methods=['GET'])
def get_system_info():
    """Get basic system information (non-sensitive)"""
    try:
        import os
        import platform
        
        system_info = {
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'api_version': '1.0.0',
            'environment': os.getenv('FLASK_ENV', 'production'),
            'uptime_check': datetime.utcnow().isoformat()
        }
        
        # Add some basic stats if available
        stats = DatabaseService.get_system_stats()
        if stats:
            system_info['active_products'] = stats.get('total_products', 0)
            system_info['active_users'] = (
                stats.get('total_manufacturers', 0) + 
                stats.get('total_developers', 0)
            )
        
        return jsonify(system_info), 200
        
    except Exception as e:
        logger.error(f"System info error: {e}")
        return create_error_response('Internal server error', 500)