from datetime import datetime
from utils.database import get_db

class AuditLog:
    """Audit log model for database operations"""
    
    @staticmethod
    def create(log_data):
        """Create a new audit log entry"""
        db = get_db()
        log_data['timestamp'] = datetime.utcnow()
        return db.audit_logs.insert_one(log_data)
    
    @staticmethod
    def find_with_filters(filter_query, page=1, limit=50):
        """Find audit logs with filters and pagination"""
        db = get_db()
        
        # Get logs with pagination
        logs = list(db.audit_logs.find(filter_query)
                   .sort('timestamp', -1)
                   .skip((page - 1) * limit)
                   .limit(limit))
        
        # Get total count
        total = db.audit_logs.count_documents(filter_query)
        
        return logs, total
    
    @staticmethod
    def build_filter(action=None, start_date=None, end_date=None):
        """Build filter query for audit logs"""
        filter_query = {}
        
        if action:
            filter_query['action'] = action
            
        if start_date or end_date:
            filter_query['timestamp'] = {}
            if start_date:
                filter_query['timestamp']['$gte'] = datetime.fromisoformat(
                    start_date.replace('Z', '+00:00')
                )
            if end_date:
                filter_query['timestamp']['$lte'] = datetime.fromisoformat(
                    end_date.replace('Z', '+00:00')
                )
        
        return filter_query