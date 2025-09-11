from datetime import datetime, timedelta
from typing import  Optional, Tuple
import pytz


def get_date_range(time_range: str, end_date: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """
    Helper function to calculate date range for analytics queries.
    
    Args:
        time_range: String representing the time range ('7d', '30d', '90d', '1y')
        end_date: Optional end date (defaults to current UTC time)
    
    Returns:
        Tuple of (start_date, end_date) as datetime objects
        
    Raises:
        ValueError: If time_range format is invalid
    """
    if end_date is None:
        end_date = datetime.utcnow()
    
    # Ensure end_date is timezone-aware (UTC)
    if end_date.tzinfo is None:
        end_date = end_date.replace(tzinfo=pytz.UTC)
    
    # Time range mapping
    time_deltas = {
        '7d': 7,
        '14d': 14,
        '30d': 30,
        '90d': 90,
        '1y': 365,
        '6m': 180,  #6 months
        '3m': 90,   #3 months
        '1m': 30    #1 month
    }
    
    # Get days or default to 7
    days = time_deltas.get(time_range, 7)
    
    # Calculate start date
    start_date = end_date - timedelta(days=days)
    
    return start_date, end_date


def get_date_range_dict(time_range: str, end_date: Optional[datetime] = None) -> dict:
    """
    Return date range as serializable dictionary.
    
    Returns:
        Dict with start_date, end_date, and metadata
    """
    start_date, end_date = get_date_range(time_range, end_date)
    
    # FIX: Convert timedelta to integer days for JSON serialization
    days_count = (end_date - start_date).days
    
    return {
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'time_range': time_range,
        'days_count': days_count,  # Now it's an integer, not timedelta
        'range_label': get_time_range_label(time_range)
    }

def get_time_range_label(time_range: str) -> str:
    """Get human-readable label for time range"""
    labels = {
        '7d': 'Last 7 Days',
        '30d': 'Last 30 Days',
        '90d': 'Last 90 Days',
        '1y': 'Last Year',
        '6m': 'Last 6 Months',
        '3m': 'Last 3 Months',
        '1m': 'Last Month'
    }
    return labels.get(time_range, 'Last 7 Days')

# For database queries - returns just the start date
def get_start_date(time_range: str) -> datetime:
    """
    Get just the start date for database queries.
    Returns timezone-aware datetime.
    """
    start_date, _ = get_date_range(time_range)
    return start_date

# Validate time range
def is_valid_time_range(time_range: str) -> bool:
    """Check if time range is valid"""
    valid_ranges = ['7d', '30d', '90d', '1y', '6m', '3m', '1m']
    return time_range in valid_ranges
