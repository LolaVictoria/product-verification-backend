from datetime import datetime, timezone, timedelta
from typing import Tuple, Dict, Any, Optional

class DateHelpersUtils:
    @staticmethod
    def get_date_range(time_range: str, end_date: Optional[datetime] = None) -> Tuple[datetime, datetime]:
        """Calculate date range for analytics queries"""
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        
        # Ensure end_date is timezone-aware (UTC)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)
        
        # Time range mapping
        time_deltas = {
            '7d': 7,
            '14d': 14,
            '30d': 30,
            '90d': 90,
            '1y': 365,
            '6m': 180,
            '3m': 90,
            '1m': 30
        }
        
        days = time_deltas.get(time_range, 7)
        start_date = end_date - timedelta(days=days)
        
        return start_date, end_date

    @staticmethod
    def get_date_range_dict(time_range: str, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Return date range as serializable dictionary"""
        start_date, end_date = DateHelpersUtils.get_date_range(time_range, end_date)
        days_count = (end_date - start_date).days
        
        return {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'time_range': time_range,
            'days_count': days_count,
            'range_label': DateHelpersUtils.get_time_range_label(time_range)
        }

    @staticmethod
    def get_time_range_label(time_range: str) -> str:
        """Get human-readable label for time range"""
        labels = {
            '7d': 'Last 7 Days',
            '14d': 'Last 14 Days',
            '30d': 'Last 30 Days',
            '90d': 'Last 90 Days',
            '1y': 'Last Year',
            '6m': 'Last 6 Months',
            '3m': 'Last 3 Months',
            '1m': 'Last Month'
        }
        return labels.get(time_range, 'Last 7 Days')

    @staticmethod
    def get_start_date(time_range: str) -> datetime:
        """Get just the start date for database queries"""
        start_date, _ = DateHelpersUtils.get_date_range(time_range)
        return start_date

    @staticmethod
    def is_valid_time_range(time_range: str) -> bool:
        """Check if time range is valid"""
        valid_ranges = ['7d', '14d', '30d', '90d', '1y', '6m', '3m', '1m']
        return time_range in valid_ranges

    @staticmethod
    def format_analytics_response(data, time_range: str) -> Dict[str, Any]:
        """Format analytics data for consistent API response"""
        return {
            'time_range': time_range,
            'data_points': len(data) if isinstance(data, list) else 1,
            'data': data,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'date_range': DateHelpersUtils.get_date_range_dict(time_range)
        }

    @staticmethod
    def get_current_utc() -> datetime:
        """Get current UTC datetime"""
        return datetime.now(timezone.utc)

    @staticmethod
    def parse_iso_date(date_string: str) -> Optional[datetime]:
        """Parse ISO date string to datetime object"""
        try:
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def format_datetime_for_display(dt: datetime, format_string: str = '%Y-%m-%d %H:%M:%S UTC') -> str:
        """Format datetime for display"""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        elif dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)
        
        return dt.strftime(format_string)

    @staticmethod
    def get_day_start(date: datetime) -> datetime:
        """Get start of day (00:00:00) for given date"""
        return date.replace(hour=0, minute=0, second=0, microsecond=0)

    @staticmethod
    def get_day_end(date: datetime) -> datetime:
        """Get end of day (23:59:59) for given date"""
        return date.replace(hour=23, minute=59, second=59, microsecond=999999)

    @staticmethod
    def days_between(start_date: datetime, end_date: datetime) -> int:
        """Calculate number of days between two dates"""
        return (end_date - start_date).days

    @staticmethod
    def is_recent(date: datetime, hours: int = 24) -> bool:
        """Check if date is within recent hours"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return date >= cutoff

date_helper_utils = DateHelpersUtils