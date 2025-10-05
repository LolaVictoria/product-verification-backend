"""
Pagination Utilities
Pure functions for handling pagination
"""

import math
from typing import Dict, Any, Tuple


def validate_pagination_params(
    page: Any = 1, 
    per_page: Any = 20, 
    max_per_page: int = 100
) -> Dict[str, int]:
    """
    Validate and normalize pagination parameters
    
    Args:
        page: Page number (can be string or int)
        per_page: Items per page (can be string or int)
        max_per_page: Maximum allowed items per page
        
    Returns:
        Dict with validated page, per_page, and skip values
    """
    try:
        page = int(page) if page else 1
        per_page = int(per_page) if per_page else 20
    except (ValueError, TypeError):
        page = 1
        per_page = 20
    
    # Ensure minimum values
    page = max(1, page)
    per_page = max(1, min(per_page, max_per_page))
    
    # Calculate skip value for database queries
    skip = (page - 1) * per_page
    
    return {
        'page': page,
        'per_page': per_page,
        'skip': skip
    }


def create_pagination_metadata(
    total_count: int, 
    page: int, 
    per_page: int
) -> Dict[str, Any]:
    """
    Create pagination metadata for API response
    
    Args:
        total_count: Total number of items
        page: Current page number
        per_page: Items per page
        
    Returns:
        Dict with pagination metadata
    """
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


def paginate_list(
    items: list, 
    page: int = 1, 
    per_page: int = 20
) -> Tuple[list, Dict[str, Any]]:
    """
    Paginate a list in memory
    
    Args:
        items: List of items to paginate
        page: Page number
        per_page: Items per page
        
    Returns:
        Tuple of (paginated_items, pagination_metadata)
    """
    params = validate_pagination_params(page, per_page)
    
    start = params['skip']
    end = start + params['per_page']
    
    paginated_items = items[start:end]
    metadata = create_pagination_metadata(len(items), params['page'], params['per_page'])
    
    return paginated_items, metadata


def get_page_range(
    current_page: int, 
    total_pages: int, 
    max_pages_shown: int = 5
) -> list:
    """
    Get range of page numbers to show in pagination UI
    
    Args:
        current_page: Current page number
        total_pages: Total number of pages
        max_pages_shown: Maximum page numbers to show
        
    Returns:
        List of page numbers to display
    """
    if total_pages <= max_pages_shown:
        return list(range(1, total_pages + 1))
    
    # Calculate range around current page
    half = max_pages_shown // 2
    
    if current_page <= half:
        return list(range(1, max_pages_shown + 1))
    elif current_page >= total_pages - half:
        return list(range(total_pages - max_pages_shown + 1, total_pages + 1))
    else:
        return list(range(current_page - half, current_page + half + 1))


def calculate_page_from_offset(offset: int, limit: int) -> int:
    """
    Calculate page number from offset and limit
    
    Args:
        offset: Offset value
        limit: Limit/per_page value
        
    Returns:
        Page number
    """
    if limit <= 0:
        return 1
    
    return (offset // limit) + 1


def calculate_offset_from_page(page: int, per_page: int) -> int:
    """
    Calculate offset from page number and per_page
    
    Args:
        page: Page number
        per_page: Items per page
        
    Returns:
        Offset value
    """
    return (max(1, page) - 1) * per_page


class Paginator:
    """
    Advanced pagination utility class for complex scenarios
    """
    
    def __init__(self, page: int = 1, per_page: int = 20, max_per_page: int = 100):
        """
        Initialize paginator
        
        Args:
            page: Page number
            per_page: Items per page
            max_per_page: Maximum allowed items per page
        """
        self.params = validate_pagination_params(page, per_page, max_per_page)
        self.page = self.params['page']
        self.per_page = self.params['per_page']
        self.skip = self.params['skip']
    
    def apply_to_query(self, query):
        """
        Apply pagination to MongoDB query
        
        Args:
            query: MongoDB cursor
            
        Returns:
            Paginated cursor
        """
        return query.skip(self.skip).limit(self.per_page)
    
    def create_response(self, data: list, total_count: int) -> Dict[str, Any]:
        """
        Create paginated response
        
        Args:
            data: List of items for current page
            total_count: Total number of items
            
        Returns:
            Dict with data and pagination metadata
        """
        metadata = create_pagination_metadata(total_count, self.page, self.per_page)
        
        return {
            'data': data,
            'pagination': metadata
        }
    
    def get_range_info(self, total_count: int) -> Dict[str, int]:
        """
        Get range information (showing X-Y of Z)
        
        Args:
            total_count: Total number of items
            
        Returns:
            Dict with start, end, and total
        """
        if total_count == 0:
            return {'start': 0, 'end': 0, 'total': 0}
        
        start = self.skip + 1
        end = min(self.skip + self.per_page, total_count)
        
        return {
            'start': start,
            'end': end,
            'total': total_count
        }

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



#################