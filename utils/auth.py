"""
Authentication utilities for API route protection
"""
import jwt
import functools
import bcrypt
from flask import request, jsonify, current_app, g
from utils.database import get_db_connection
from datetime import datetime, timedelta
import logging
from dotenv import load_dotenv
import os 

load_dotenv()
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

class AuthError(Exception):
    """Custom authentication exception"""
    pass

def generate_token(user_data, role):
    """Generate JWT token for user"""
    try:
        payload = {
            'user_id': user_data['user_id'],
            'email': user_data.get('email'),
            'role': role,
            'manufacturer_id': user_data.get('manufacturer_id'),
            'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        return token
    except Exception as e:
        logger.error(f"Error generating token: {e}")
        raise AuthError("Token generation failed")

def verify_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token")

def get_token_from_request():
    """Extract token from request headers"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        raise AuthError("No authorization header")
    
    try:
        # Expect format: "Bearer <token>"
        token = auth_header.split(' ')[1]
        return token
    except IndexError:
        raise AuthError("Invalid authorization header format")

def get_current_user():
    """Get current user from token"""
    try:
        token = get_token_from_request()
        payload = verify_token(token)
        
        # Store in Flask g object for request scope
        g.current_user = payload
        
        return payload
    except AuthError:
        raise

def require_auth(f):
    """Decorator to require authentication for any route"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_user = get_current_user()
            request.current_user = current_user
            return f(*args, **kwargs)
        except AuthError as e:
            return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_user = get_current_user()
            
            if current_user.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            request.current_user = current_user
            return f(*args, **kwargs)
            
        except AuthError as e:
            return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
        except Exception as e:
            logger.error(f"Admin auth error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_manufacturer_auth(f):
    """Decorator to require manufacturer role"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_user = get_current_user()
            
            if current_user.get('role') != 'manufacturer':
                return jsonify({'error': 'Manufacturer access required'}), 403
            
            # Verify manufacturer exists and is active
            manufacturer_id = current_user.get('manufacturer_id')
            if not manufacturer_id:
                return jsonify({'error': 'No manufacturer ID in token'}), 401
            
            db = get_db_connection()
            manufacturer = db.manufacturers.find_one({
                'manufacturer_id': manufacturer_id,
                'verification_status': 'verified'
            })
            
            if not manufacturer:
                return jsonify({'error': 'Manufacturer not found or not verified'}), 401
            
            request.current_user = current_user
            return f(*args, **kwargs)
            
        except AuthError as e:
            return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
        except Exception as e:
            logger.error(f"Manufacturer auth error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                current_user = get_current_user()
                
                user_role = current_user.get('role')
                if user_role != required_role:
                    return jsonify({
                        'error': f'{required_role.title()} access required',
                        'user_role': user_role
                    }), 403
                
                request.current_user = current_user
                return f(*args, **kwargs)
                
            except AuthError as e:
                return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
            except Exception as e:
                logger.error(f"Role auth error: {e}")
                return jsonify({'error': 'Authentication failed'}), 401
        
        return decorated_function
    return decorator

# FIXED PASSWORD VERIFICATION FUNCTIONS
def verify_password_bcrypt(password, password_hash):
    """Verify password against bcrypt hash"""
    try:
        if not password or not password_hash:
            return False
        
        # Convert string password to bytes
        password_bytes = password.encode('utf-8')
        
        # Convert hash to bytes if it's a string
        if isinstance(password_hash, str):
            hash_bytes = password_hash.encode('utf-8')
        else:
            hash_bytes = password_hash
        
        # Use bcrypt to verify
        return bcrypt.checkpw(password_bytes, hash_bytes)
    
    except Exception as e:
        logger.error(f"Bcrypt password verification error: {e}")
        return False

def verify_password_with_security_utils(email, password):
    """Use security_utils password verification system"""
    try:
        # Import here to avoid circular imports
        from utils.security import security_utils
        from utils.users import get_user_by_email
        
        user = get_user_by_email(email)
        if not user:
            return False
        
        stored_hash = user.get('password_hash') or user.get('password')
        if not stored_hash:
            return False
            
        return security_utils.verify_password(stored_hash, password)
    
    except Exception as e:
        logger.error(f"Security utils password verification error: {e}")
        return False

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

def authenticate_admin(email, password):
    """Authenticate admin user from users collection"""
    try:
        print(f"Authenticating admin: {email}")
        
        db = get_db_connection()
        
        # Find admin in users collection
        admin = db.users.find_one({
            'email': email,
            'role': 'admin'
        })
        
        print(f"Admin found: {bool(admin)}")
        
        if not admin:
            raise AuthError("Invalid credentials")
        
        # Check if admin is active/verified if you have such fields
        if admin.get('is_active') == False:
            raise AuthError("Admin account is deactivated")
        
        if admin.get('verification_status') and admin.get('verification_status') not in ['verified', 'pending']:
            raise AuthError("Admin account not verified")
        
        # Get stored password hash
        stored_hash = admin.get('password_hash') or admin.get('password')
        if not stored_hash:
            raise AuthError("Invalid credentials")
        
        print(f"Stored hash type: {type(stored_hash)}")
        print(f"Stored hash starts with: {str(stored_hash)[:10]}...")
        
        # Verify password - try security_utils first, then bcrypt
        password_valid = False
        
        try:
            # Try security_utils method first
            password_valid = verify_password_with_security_utils(email, password)
            print(f"Security utils verification: {password_valid}")
        except Exception as e:
            print(f"Security utils failed: {e}")
        
        if not password_valid:
            try:
                # Try direct bcrypt verification
                password_valid = verify_password_bcrypt(password, stored_hash)
                print(f"Bcrypt verification: {password_valid}")
            except Exception as e:
                print(f"Bcrypt verification failed: {e}")
        
        if not password_valid:
            raise AuthError("Invalid credentials")
        
        # Generate token
        user_data = {
            'user_id': str(admin['_id']),
            'email': admin.get('primary_email') or admin.get('email')
        }
        
        token = generate_token(user_data, 'admin')
        
        # Log successful login
        try:
            log_security_event('admin_login', admin['_id'], request.remote_addr)
        except Exception as e:
            print(f"Security logging failed: {e}")
        
        return {
            'token': token,
            'user': {
                'id': str(admin['_id']),
                'email': admin.get('primary_email') or admin.get('email'),
                'role': 'admin',
                'name': admin.get('name'),
                'username': admin.get('username')
            }
        }
        
    except AuthError:
        raise
    except Exception as e:
        print(f"Admin authentication error: {e}")
        import traceback
        print(traceback.format_exc())
        raise AuthError("Authentication failed")

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
        
        # Verify password using same methods as admin
        password_valid = False
        
        try:
            # Try security_utils method first
            password_valid = verify_password_with_security_utils(email, password)
        except Exception as e:
            print(f"Security utils failed for manufacturer: {e}")
        
        if not password_valid:
            try:
                # Try direct bcrypt verification
                password_valid = verify_password_bcrypt(password, stored_hash)
            except Exception as e:
                print(f"Bcrypt verification failed for manufacturer: {e}")
        
        if not password_valid:
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
            log_security_event('manufacturer_login', manufacturer['_id'], request.remote_addr)
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

# Remove the old SHA256 functions - they're incompatible with bcrypt
# def verify_password(password, password_hash):  # REMOVED
# def hash_password(password):  # REMOVED

# Debug function to check your collections
def debug_user_collections():
    """Debug function to see what's in your collections"""
    try:
        db = get_db_connection()
        
        collections = db.list_collection_names()
        print(f"Available collections: {collections}")
        
        # Check users collection
        if 'users' in collections:
            admin_count = db.users.count_documents({'role': 'admin'})
            customer_count = db.users.count_documents({'role': 'customer'})
            print(f"Users collection - Admins: {admin_count}, Customers: {customer_count}")
            
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