# services/auth_service.py
import os
from datetime import datetime
from flask import request, g
from app.utils.formatters import format_user_response
from app.config.database import get_db_connection
import logging
from dotenv import load_dotenv
from app.utils.password_utils import verify_password
from app.utils.token_utils import generate_token
load_dotenv()
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

class AuthError(Exception):
    """Custom authentication exception"""
    pass

class AuthService:
    """Service for handling authentication operations"""
    
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY')
        self.token_expiry_hours = int(os.getenv('TOKEN_EXPIRY_HOURS', '24'))
   
    @staticmethod
    def authenticate_customer(email, password):
        """Authenticate customer from users collection"""
        try:
            print(f"Authenticating customer: {email}")
            
            db = get_db_connection()
            
            # Find customer in users collection
            customer = db.users.find_one({
                'email': email,
                'role': 'customer'
            })
            
            if not customer:
                customer = db.users.find_one({
                    'primary_email': email,
                    'role': 'customer'
                })
            
            print(f"Customer found: {bool(customer)}")
            
            if not customer:
                raise AuthError("Invalid credentials")
            
            # Check if customer is active
            if customer.get('is_active') == False:
                raise AuthError("Customer account is deactivated")
            
            # Get stored password hash
            stored_hash = customer.get('password_hash') or customer.get('password')
            if not stored_hash:
                raise AuthError("Invalid credentials")
            
            # Verify password - FIXED: correct parameter order
            if not verify_password(password, stored_hash):
                raise AuthError("Invalid credentials")
            
            # Generate token
            user_data = {
                'user_id': str(customer['_id']),
                'email': customer.get('primary_email') or customer.get('email')
            }
            
            token = generate_token(user_data, 'customer')
            
            # Log successful login
            try:
                AuthService.log_security_event('customer_login', customer['_id'], request.remote_addr)
            except Exception as e:
                print(f"Security logging failed: {e}")
            
            return {
                'token': token,
                'user': format_user_response(customer, 'customer')
            }
            
        except AuthError:
            raise
        except Exception as e:
            print(f"Customer authentication error: {e}")
            import traceback
            print(traceback.format_exc())
            raise AuthError("Authentication failed")
    
    @staticmethod
    def authenticate_admin(email, password):
        """Authenticate admin user from admins collection"""
        try:
            print(f"Authenticating admin: {email}")
            
            db = get_db_connection()
            
            # Find admin in admins collection
            admin = db.admins.find_one({
                'email': email,
                'role': 'admin'
            })
            
            print(f"Admin found: {bool(admin)}")
            
            if not admin:
                raise AuthError("Invalid credentials")
            
            # Check if admin is active
            if admin.get('is_active') == False:
                raise AuthError("Admin account is deactivated")
            
            # Get stored password hash
            stored_hash = admin.get('password_hash') or admin.get('password')
            if not stored_hash:
                raise AuthError("Invalid credentials")
            
            print(f"Stored hash type: {type(stored_hash)}")
            print(f"Stored hash starts with: {str(stored_hash)[:10]}...")
            
            # Verify password - FIXED: correct parameter order
            password_valid = verify_password(password, stored_hash)
            print(f"Password verification result: {password_valid}")
            
            if not password_valid:
                raise AuthError("Invalid credentials")
            
            # Generate token
            user_data = {
                'user_id': str(admin['_id']),
                'email': admin.get('email')
            }
            
            token = generate_token(user_data, 'admin')
            
            # Log successful login
            try:
                AuthService.log_security_event('admin_login', admin['_id'], request.remote_addr)
            except Exception as e:
                print(f"Security logging failed: {e}")
            
            return {
                'token': token,
                'user': format_user_response(admin, 'admin')
            }
            
        except AuthError:
            raise
        except Exception as e:
            print(f"Admin authentication error: {e}")
            import traceback
            print(traceback.format_exc())
            raise AuthError("Authentication failed")

    @staticmethod
    def authenticate_manufacturer(email, password):
        """Authenticate manufacturer from manufacturers collection"""
        try:
            print(f"Authenticating manufacturer: {email}")
            
            db = get_db_connection()
            
            # Find manufacturer in manufacturers collection
            manufacturer = db.manufacturers.find_one({
                'contact_email': email
            })
            
            if not manufacturer:
                manufacturer = db.manufacturers.find_one({
                    'email': email
                })
            
            if not manufacturer:
                manufacturer = db.manufacturers.find_one({
                    'primary_email': email
                })
            
            print(f"Manufacturer found: {bool(manufacturer)}")
            
            if not manufacturer:
                raise AuthError("Invalid credentials")
            
            # Check verification status
            if manufacturer.get('verification_status') != 'verified':
                raise AuthError("Manufacturer account not verified")
            
            # Check if manufacturer is active
            if manufacturer.get('is_active') == False:
                raise AuthError("Manufacturer account is deactivated")
            
            # Get stored password hash
            stored_hash = manufacturer.get('password_hash') or manufacturer.get('password')
            if not stored_hash:
                raise AuthError("Invalid credentials")
            
            # Verify password - FIXED: correct parameter order
            if not verify_password(password, stored_hash):
                raise AuthError("Invalid credentials")
            
            # Generate token
            user_data = {
                'user_id': str(manufacturer['_id']),
                'email': manufacturer.get('contact_email') or manufacturer.get('email'),
                'manufacturer_id': manufacturer.get('manufacturer_id')
            }
            
            token = generate_token(user_data, 'manufacturer')
            
            # Log successful login
            try:
                AuthService.log_security_event('manufacturer_login', manufacturer['_id'], request.remote_addr)
            except Exception as e:
                print(f"Security logging failed: {e}")
            
            return {
                'token': token,
                'user': {
                    'id': str(manufacturer['_id']),
                    'email': manufacturer.get('contact_email') or manufacturer.get('email'),
                    'role': 'manufacturer',
                    'manufacturer_id': manufacturer.get('manufacturer_id'),
                    'company_name': manufacturer.get('company_name'),
                    'name': manufacturer.get('contact_name') or manufacturer.get('name')
                }
            }
            
        except AuthError:
            raise
        except Exception as e:
            print(f"Manufacturer authentication error: {e}")
            import traceback
            print(traceback.format_exc())
            raise AuthError("Authentication failed")
        
    @staticmethod
    def get_current_user():
        """Get current user from token"""
        try:
            token = AuthService.get_token_from_request()
            payload = AuthService.verify_token(token)
            
            # Store in Flask g object for request scope
            g.current_user = payload
            
            return payload
        except AuthError:
            raise

    @staticmethod
    def log_security_event(event_type, user_id, ip_address):
        """Log security-related events"""
        try:
            db = get_db_connection()
            
            security_log = {
                'event_type': event_type,
                'user_id': str(user_id),
                'ip_address': ip_address,
                'timestamp': datetime.now(),
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
            db.security_logs.insert_one(security_log)
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")

    def debug_user_collections():
        """Debug function to see what's in your collections"""
        try:
            db = get_db_connection()
            
            collections = db.list_collection_names()
            # Check users collection
            if 'users' in collections:
                admin_count = db.users.count_documents({'role': 'admin'})
                customer_count = db.users.count_documents({'role': 'customer'})
                
                # Show sample admin
                sample_admin = db.users.find_one({'role': 'admin'})
                if sample_admin:
                    print(f"Sample admin fields: {list(sample_admin.keys())}")
                    print(f"Sample admin email: {sample_admin.get('email') or sample_admin.get('primary_email')}")
                    print(f"Sample admin password hash: {str(sample_admin.get('password_hash', 'No password_hash'))[:20]}...")
            
            # Check manufacturers collection
            if 'manufacturers' in collections:
                mfg_count = db.manufacturers.count_documents({})
                verified_mfg = db.manufacturers.count_documents({'verification_status': 'verified'})
                print(f"Manufacturers collection - Total: {mfg_count}, Verified: {verified_mfg}")
                
                # Show sample manufacturer
                sample_mfg = db.manufacturers.find_one({})
                if sample_mfg:
                    print(f"Sample manufacturer fields: {list(sample_mfg.keys())}")
            
            return {
                'collections': collections,
                'stats': 'printed to console'
            }
            
        except Exception as e:
            print(f"Debug error: {e}")
            return {'error': str(e)}


auth_service = AuthService()