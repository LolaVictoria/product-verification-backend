# app/monitoring/health.py
from flask import Blueprint, jsonify
from app.config.database import get_db_connection
from datetime import datetime, timezone
import psutil
import os

health_bp = Blueprint('health', __name__)

@health_bp.route('/health')
def health_check():
    checks = {
        'database': check_database(),
        'memory': check_memory(),
        'disk': check_disk_space(),
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    overall_status = 'healthy' if all(
        check['status'] == 'healthy' for check in checks.values() 
        if isinstance(check, dict) and 'status' in check
    ) else 'unhealthy'
    
    status_code = 200 if overall_status == 'healthy' else 503
    
    return jsonify({
        'status': overall_status,
        'checks': checks
    }), status_code

def check_database():
    try:
        db = get_db_connection()
        db.admin.command('ping')
        return {'status': 'healthy', 'message': 'Database connected'}
    except Exception as e:
        return {'status': 'unhealthy', 'error': str(e)}

def check_memory():
    memory = psutil.virtual_memory()
    if memory.percent > 90:
        return {'status': 'unhealthy', 'usage_percent': memory.percent}
    return {'status': 'healthy', 'usage_percent': memory.percent}

def check_disk_space():
    disk = psutil.disk_usage('/')
    if disk.percent > 85:
        return {'status': 'unhealthy', 'usage_percent': disk.percent}
    return {'status': 'healthy', 'usage_percent': disk.percent}