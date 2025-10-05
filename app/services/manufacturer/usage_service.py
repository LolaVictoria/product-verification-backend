import logging
import pymongo
from app.utils.date_helpers import date_helper_utils
from bson import ObjectId
logger = logging.getLogger(__name__)
class UsageService:
    """Handles API usage logging and rate limiting"""
    def __init__(self, db):
        self.db = db

    def log_api_usage(self, manufacturer_id: str, endpoint: str, request_count: int = 1) -> None:
        """Log API usage and increment usage counter"""
        try:
            if not ObjectId.is_valid(manufacturer_id):
                raise ValueError("Invalid manufacturer ID")

            self.db.api_usage_logs.insert_one({
                'manufacturer_id': ObjectId(manufacturer_id),
                'endpoint': endpoint,
                'timestamp': date_helper_utils.get_current_utc(),
                'request_count': request_count
            })
            self._increment_usage(ObjectId(manufacturer_id), endpoint)

        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error logging API usage for {manufacturer_id}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error logging API usage for {manufacturer_id}: {str(e)}")
            raise

    def _increment_usage(self, manufacturer_id: ObjectId, endpoint: str) -> None:
        """Increment usage counter for rate limiting"""
        try:
            self.db.manufacturer_usage.update_one(
                {'manufacturer_id': manufacturer_id, 'endpoint': endpoint},
                {
                    '$set': {'updated_at': date_helper_utils.get_current_utc()},
                    '$inc': {'request_count': 1}
                },
                upsert=True
            )
        except pymongo.errors.PyMongoError as e:
            logger.error(f"Database error incrementing usage: {str(e)}")
            raise

usage_service = UsageService()