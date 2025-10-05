"""
Database Query Utilities
Pure functions for building and manipulating database queries
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta


def build_filter_query(filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build MongoDB filter query from parameters
    
    Args:
        filters: Dictionary of filter parameters
        
    Returns:
        MongoDB query dictionary
    """
    query = {}
    
    # Text search
    if filters.get('search'):
        search_term = filters['search']
        query['$or'] = [
            {'serial_number': {'$regex': search_term, '$options': 'i'}},
            {'brand': {'$regex': search_term, '$options': 'i'}},
            {'model': {'$regex': search_term, '$options': 'i'}},
            {'manufacturer_name': {'$regex': search_term, '$options': 'i'}}
        ]
    
    # Date range filter
    if filters.get('start_date') or filters.get('end_date'):
        date_filter = {}
        
        if filters.get('start_date'):
            try:
                start_date = datetime.fromisoformat(filters['start_date'].replace('Z', '+00:00'))
                date_filter['$gte'] = start_date
            except ValueError:
                pass
        
        if filters.get('end_date'):
            try:
                end_date = datetime.fromisoformat(filters['end_date'].replace('Z', '+00:00'))
                date_filter['$lte'] = end_date
            except ValueError:
                pass
        
        if date_filter:
            query['created_at'] = date_filter
    
    # Category filter
    if filters.get('category'):
        query['device_type'] = filters['category']
    
    # Registration type filter
    if filters.get('registration_type'):
        query['registration_type'] = filters['registration_type']
    
    # Manufacturer filter
    if filters.get('manufacturer_id'):
        query['manufacturer_id'] = filters['manufacturer_id']
    
    # Status filter
    if filters.get('status'):
        query['status'] = filters['status']
    
    return query


def calculate_success_rate(successful: int, total: int) -> float:
    """
    Calculate success rate percentage
    
    Args:
        successful: Number of successful operations
        total: Total number of operations
        
    Returns:
        Success rate as percentage (0-100)
    """
    if total == 0:
        return 0.0
    
    return round((successful / total) * 100, 1)


def parse_time_range(time_range: str) -> int:
    """
    Parse time range string to number of days
    
    Args:
        time_range: Time range string (e.g., '7d', '30d', '1y')
        
    Returns:
        Number of days
    """
    time_ranges = {
        '7d': 7,
        '14d': 14,
        '30d': 30,
        '90d': 90,
        '1y': 365,
        '6m': 180,
        '3m': 90,
        '1m': 30,
        '1w': 7,
        '2w': 14
    }
    
    return time_ranges.get(time_range, 7)


def build_sort_query(sort_by: str, order: str = 'desc') -> list:
    """
    Build MongoDB sort query
    
    Args:
        sort_by: Field to sort by
        order: Sort order ('asc' or 'desc')
        
    Returns:
        MongoDB sort list
    """
    direction = 1 if order.lower() == 'asc' else -1
    return [(sort_by, direction)]


def build_projection(fields: list, include: bool = True) -> Dict[str, int]:
    """
    Build MongoDB projection dictionary
    
    Args:
        fields: List of field names
        include: True to include fields, False to exclude
        
    Returns:
        MongoDB projection dictionary
    """
    value = 1 if include else 0
    return {field: value for field in fields}