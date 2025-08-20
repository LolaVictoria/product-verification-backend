from flask import Blueprint, request, jsonify
from middleware.auth import authenticate_admin
from models.audit_log import AuditLog
from utils.helpers import convert_objectids_to_strings

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/audit-logs', methods=['GET'])
@authenticate_admin
def get_audit_logs():
    """Get audit logs with filtering and pagination"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        action = request.args.get('action')
        start_date = request.args.get('startDate')
        end_date = request.args.get('endDate')
        admin_email = request.args.get('adminEmail')
        
        # Validate pagination
        if page < 1:
            page = 1
        if limit < 1 or limit > 100:
            limit = 50
        
        # Build filter query
        filter_query = AuditLog.build_filter(action, start_date, end_date)
        
        # Add admin email filter if provided
        if admin_email:
            filter_query['admin_email'] = admin_email
        
        # Get audit logs
        audit_logs, total = AuditLog.find_with_filters(filter_query, page, limit)
        
        # Convert ObjectIds to strings
        audit_logs = convert_objectids_to_strings(audit_logs)
        
        return jsonify({
            'success': True,
            'data': audit_logs,
            'pagination': {
                'current_page': page,
                'total_pages': (total + limit - 1) // limit,
                'total_items': total,
                'items_per_page': limit,
                'has_next': page * limit < total,
                'has_prev': page > 1
            },
            'filters': {
                'action': action,
                'start_date': start_date,
                'end_date': end_date,
                'admin_email': admin_email
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Failed to fetch audit logs',
            'error': str(e) if request.args.get('debug') else None
        }), 500

@audit_bp.route('/audit-logs/actions', methods=['GET'])
@authenticate_admin
def get_audit_actions():
    """Get list of available audit log actions"""
    try:
        from utils.database import get_db
        db = get_db()
        
        # Get distinct actions from audit logs
        actions = db.audit_logs.distinct('action')
        
        return jsonify({
            'success': True,
            'data': sorted(actions),
            'count': len(actions)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Failed to fetch audit actions',
            'error': str(e) if request.args.get('debug') else None
        }), 500

@audit_bp.route('/audit-logs/stats', methods=['GET'])
@authenticate_admin
def get_audit_stats():
    """Get audit log statistics"""
    try:
        from utils.database import get_db
        from datetime import datetime, timedelta
        
        db = get_db()
        
        # Get stats for last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        total_logs = db.audit_logs.count_documents({})
        recent_logs = db.audit_logs.count_documents({
            'timestamp': {'$gte': thirty_days_ago}
        })
        
        # Get action breakdown
        pipeline = [
            {'$group': {'_id': '$action', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        action_stats = list(db.audit_logs.aggregate(pipeline))
        
        return jsonify({
            'success': True,
            'data': {
                'total_logs': total_logs,
                'recent_logs': recent_logs,
                'action_breakdown': action_stats,
                'period': '30 days'
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Failed to fetch audit statistics',
            'error': str(e) if request.args.get('debug') else None
        }), 500
