from typing import Dict, Any, Tuple, Optional
import math

def validate_pagination_params(page: int = 1, per_page: int = 20, max_per_page: int = 100) -> Dict[str, int]:
    """Validate and normalize pagination parameters"""
    page = max(1, int(page))
    per_page = min(max_per_page, max(1, int(per_page)))
    skip = (page - 1) * per_page
    
    return {
        'page': page,
        'per_page': per_page,
        'skip': skip
    }

def create_pagination_response(total_count: int, page: int, per_page: int) -> Dict[str, Any]:
    """Create pagination metadata for API response"""
    total_pages = math.ceil(total_count / per_page) if per_page > 0 else 0
    
    return {
        'page': page,
        'per_page': per_page,
        'total_items': total_count,
        'total_pages': total_pages,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1 if page < total_pages else None,
        'prev_page': page - 1 if page > 1 else None
    }

def paginate_query_result(query_result, total_count: int, page: int, per_page: int) -> Dict[str, Any]:
    """Paginate query result with metadata"""
    pagination_info = create_pagination_response(total_count, page, per_page)
    
    return {
        'data': query_result,
        'pagination': pagination_info
    }

class Paginator:
    """Advanced pagination utility class"""
    
    def __init__(self, page: int = 1, per_page: int = 20, max_per_page: int = 100):
        self.params = validate_pagination_params(page, per_page, max_per_page)
        self.page = self.params['page']
        self.per_page = self.params['per_page']
        self.skip = self.params['skip']
    
    def apply_to_query(self, query):
        """Apply pagination to MongoDB query"""
        return query.skip(self.skip).limit(self.per_page)
    
    def create_response(self, data, total_count: int) -> Dict[str, Any]:
        """Create paginated response"""
        return paginate_query_result(data, total_count, self.page, self.per_page)
    
    def get_range_info(self, total_count: int) -> Dict[str, int]:
        """Get range information (showing X-Y of Z)"""
        if total_count == 0:
            return {'start': 0, 'end': 0, 'total': 0}
        
        start = self.skip + 1
        end = min(self.skip + self.per_page, total_count)
        
        return {'start': start, 'end': end, 'total': total_count}