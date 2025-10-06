# services/customer_service.py 
from datetime import datetime
from typing import Optional, Dict, List
from app.config.database import get_db_connection
from bson import ObjectId
import secrets
import string
import logging

logger = logging.getLogger(__name__)

class CustomerService:
    def __init__(self):
        self.db = get_db_connection()
        self.customers_collection = self.db.customers
        self.verifications_collection = self.db.verifications
    
    @staticmethod
    def create_customer_for_manufacturer(self, customer_data: Dict) -> Dict:
        """
        Create a customer account linked to a specific manufacturer
        This is called when customers register through manufacturer's website
        """
        try:
            # Validate manufacturer_id is provided
            if not customer_data.get('manufacturer_id'):
                raise ValueError("manufacturer_id is required")
            
            # Generate verification token for email verification
            verification_token = self._generate_verification_token()
            
            # Prepare customer document
            customer_doc = {
                'email': customer_data['email'].lower().strip(),
                'name': customer_data['name'].strip(),
                'phone': customer_data.get('phone', '').strip(),
                'manufacturer_id': ObjectId(customer_data['manufacturer_id']),
                'registration_source': customer_data.get('registration_source', 'web'),
                'verification_token': verification_token,
                'email_verified': False,
                'status': 'active',
                'created_at': datetime.datetime.now(datetime.UTC),
                'updated_at': datetime.datetime.now(datetime.UTC),
                'last_verification': None,
                'total_verifications': 0
            }
            
            # Insert customer
            result = self.customers_collection.insert_one(customer_doc)
            
            # Return customer with ID
            customer_doc['_id'] = result.inserted_id
            
            logger.info(f"Created customer for manufacturer: {customer_data['email']}")
            return customer_doc
            
        except Exception as e:
            logger.error(f"Error creating customer: {str(e)}")
            raise Exception(f"Failed to create customer: {str(e)}")
    
    @staticmethod
    def get_customer_by_email_and_manufacturer(self, email: str, manufacturer_id: ObjectId) -> Optional[Dict]:
        """
        Get customer by email within a specific manufacturer's scope
        """
        try:
            return self.customers_collection.find_one({
                'email': email.lower().strip(),
                'manufacturer_id': manufacturer_id
            })
        except Exception as e:
            logger.error(f"Error getting customer by email: {str(e)}")
            return None
    
    @staticmethod
    def get_customer_by_id_and_manufacturer(self, customer_id: str, manufacturer_id: ObjectId) -> Optional[Dict]:
        """
        Get customer by ID, ensuring they belong to the specified manufacturer
        """
        try:
            return self.customers_collection.find_one({
                '_id': ObjectId(customer_id),
                'manufacturer_id': manufacturer_id
            })
        except Exception as e:
            logger.error(f"Error getting customer by ID: {str(e)}")
            return None
    
    @staticmethod
    def verify_customer_email(self, verification_token: str) -> bool:
        """
        Verify customer email using verification token
        """
        try:
            result = self.customers_collection.update_one(
                {'verification_token': verification_token, 'email_verified': False},
                {
                    '$set': {
                        'email_verified': True,
                        'updated_at': datetime.datetime.now(datetime.UTC)
                    },
                    '$unset': {'verification_token': ''}
                }
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Error verifying customer email: {str(e)}")
            return False
    
    @staticmethod
    def get_manufacturer_customers(self, manufacturer_id: ObjectId, page: int = 1, limit: int = 50) -> Dict:
        """
        Get all customers for a specific manufacturer with pagination
        """
        try:
            skip = (page - 1) * limit
            
            # Get customers
            customers = list(self.customers_collection.find(
                {'manufacturer_id': manufacturer_id}
            ).skip(skip).limit(limit).sort('created_at', -1))
            
            # Get total count
            total_count = self.customers_collection.count_documents(
                {'manufacturer_id': manufacturer_id}
            )
            
            return {
                'customers': customers,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': (total_count + limit - 1) // limit
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting manufacturer customers: {str(e)}")
            return {'customers': [], 'pagination': {'page': 1, 'limit': limit, 'total': 0, 'pages': 0}}
    
    @staticmethod
    def update_customer_verification_stats(self, customer_id: ObjectId) -> None:
        """
        Update customer's verification statistics after a new verification
        """
        try:
            self.customers_collection.update_one(
                {'_id': customer_id},
                {
                    '$set': {
                        'last_verification': datetime.datetime.now(datetime.UTC),
                        'updated_at': datetime.datetime.now(datetime.UTC)
                    },
                    '$inc': {'total_verifications': 1}
                }
            )
            
        except Exception as e:
            logger.error(f"Error updating customer verification stats: {str(e)}")
    
    @staticmethod
    def get_customer_verification_summary(self, customer_id: str, manufacturer_id: ObjectId) -> Dict:
        """
        Get verification summary for a customer
        """
        try:
            # Verify customer belongs to manufacturer
            customer = self.get_customer_by_id_and_manufacturer(customer_id, manufacturer_id)
            if not customer:
                return {'error': 'Customer not found'}
            
            # Get verification statistics
            pipeline = [
                {'$match': {
                    'customer_id': ObjectId(customer_id),
                    'manufacturer_id': manufacturer_id
                }},
                {'$group': {
                    '_id': '$status',
                    'count': {'$sum': 1}
                }}
            ]
            
            verification_stats = list(self.verifications_collection.aggregate(pipeline))
            
            # Format statistics
            stats = {
                'authentic': 0,
                'counterfeit': 0,
                'suspicious': 0,
                'total': customer.get('total_verifications', 0)
            }
            
            for stat in verification_stats:
                if stat['_id'] in stats:
                    stats[stat['_id']] = stat['count']
            
            return {
                'customer_info': {
                    'id': str(customer['_id']),
                    'email': customer['email'],
                    'name': customer['name'],
                    'created_at': customer['created_at'],
                    'last_verification': customer.get('last_verification')
                },
                'verification_stats': stats
            }
            
        except Exception as e:
            logger.error(f"Error getting customer verification summary: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def search_manufacturer_customers(self, manufacturer_id: ObjectId, search_term: str, page: int = 1, limit: int = 50) -> Dict:
        """
        Search customers within a manufacturer's scope
        """
        try:
            skip = (page - 1) * limit
            
            # Create search query
            search_query = {
                'manufacturer_id': manufacturer_id,
                '$or': [
                    {'email': {'$regex': search_term, '$options': 'i'}},
                    {'name': {'$regex': search_term, '$options': 'i'}},
                    {'phone': {'$regex': search_term, '$options': 'i'}}
                ]
            }
            
            # Get customers
            customers = list(self.customers_collection.find(search_query)
                           .skip(skip).limit(limit).sort('created_at', -1))
            
            # Get total count
            total_count = self.customers_collection.count_documents(search_query)
            
            return {
                'customers': customers,
                'search_term': search_term,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_count,
                    'pages': (total_count + limit - 1) // limit
                }
            }
            
        except Exception as e:
            logger.error(f"Error searching customers: {str(e)}")
            return {'customers': [], 'pagination': {'page': 1, 'limit': limit, 'total': 0, 'pages': 0}}
    
    @staticmethod
    def _generate_verification_token(self) -> str:
        """
        Generate a secure verification token for email verification
        """
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    
    @staticmethod
    def get_customer_analytics_for_manufacturer(self, manufacturer_id: ObjectId, start_date: str = None, end_date: str = None) -> Dict:
        """
        Get customer analytics for a manufacturer
        """
        try:
            match_query = {'manufacturer_id': manufacturer_id}
            
            # Add date filters if provided
            if start_date or end_date:
                date_filter = {}
                if start_date:
                    date_filter['$gte'] = datetime.fromisoformat(start_date)
                if end_date:
                    date_filter['$lte'] = datetime.fromisoformat(end_date)
                match_query['created_at'] = date_filter
            
            # Get total customers
            total_customers = self.customers_collection.count_documents(match_query)
            
            # Get customer registration trend (daily)
            pipeline = [
                {'$match': match_query},
                {'$group': {
                    '_id': {
                        '$dateToString': {
                            'format': '%Y-%m-%d',
                            'date': '$created_at'
                        }
                    },
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id': 1}}
            ]
            
            daily_registrations = list(self.customers_collection.aggregate(pipeline))
            
            # Get verified vs unverified customers
            verified_count = self.customers_collection.count_documents({
                **match_query,
                'email_verified': True
            })
            
            return {
                'total_customers': total_customers,
                'verified_customers': verified_count,
                'unverified_customers': total_customers - verified_count,
                'daily_registrations': daily_registrations,
                'period': {
                    'start_date': start_date,
                    'end_date': end_date
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting customer analytics: {str(e)}")
            return {
                'total_customers': 0,
                'verified_customers': 0,
                'unverified_customers': 0,
                'daily_registrations': [],
                'error': str(e)
            }