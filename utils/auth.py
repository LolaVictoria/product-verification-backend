"""
Authentication utilities for API route protection
"""
import jwt
import functools
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

# Login functions to generate tokens

def authenticate_admin(email, password):
    """Authenticate admin user and generate token"""
    try:
        db = get_db_connection()
        
        # Find admin user - check both collections for flexibility
        admin = db.users.find_one({
            'primary_email': email,
            'role': 'admin',
            'verification_status': 'verified'
        })
        
        if not admin:
            # Also check if there's an admin in your existing structure
            admin = db.users.find_one({
                'email': email,
                'role': 'admin',
                'is_active': True
            })
        
        if not admin:
            raise AuthError("Admin not found")
        
        # Use your existing password verification logic
        password_field = admin.get('password_hash') or admin.get('password')
        if not verify_password_with_user_utils(email, password):
            raise AuthError("Invalid credentials")
        
        # Generate token
        user_data = {
            'user_id': str(admin['_id']),
            'email': admin.get('primary_email') or admin.get('email')
        }
        
        token = generate_token(user_data, 'admin')
        
        # Log successful login
        log_security_event('admin_login', admin['_id'], request.remote_addr)
        
        return {
            'token': token,
            'user': {
                'id': str(admin['_id']),
                'email': admin.get('primary_email') or admin.get('email'),
                'role': 'admin'
            }
        }
        
    except Exception as e:
        logger.error(f"Admin authentication error: {e}")
        raise AuthError("Authentication failed")

def authenticate_manufacturer(email, password):
    """Authenticate manufacturer and generate token"""
    try:
        db = get_db_connection()
        
        # Find manufacturer
        manufacturer = db.manufacturers.find_one({
            'contact_email': email,
            'verification_status': 'verified'
        })
        
        if not manufacturer:
            raise AuthError("Manufacturer not found")
        
        # Verify password
        if not verify_password(password, manufacturer.get('password_hash')):
            raise AuthError("Invalid credentials")
        
        # Generate token
        user_data = {
            'user_id': str(manufacturer['_id']),
            'email': manufacturer['contact_email'],
            'manufacturer_id': manufacturer['manufacturer_id']
        }
        
        token = generate_token(user_data, 'manufacturer')
        
        # Log successful login
        log_security_event('manufacturer_login', manufacturer['_id'], request.remote_addr)
        
        return {
            'token': token,
            'user': {
                'id': str(manufacturer['_id']),
                'email': manufacturer['contact_email'],
                'role': 'manufacturer',
                'manufacturer_id': manufacturer['manufacturer_id'],
                'company_name': manufacturer['company_name']
            }
        }
        
    except Exception as e:
        logger.error(f"Manufacturer authentication error: {e}")
        raise AuthError("Authentication failed")

# Import your existing user utils functions
from utils.users import get_user_by_email, verify_password as verify_password_user_utils, is_token_blacklisted

def verify_password_with_user_utils(email, password):
    """Use your existing password verification system"""
    user = get_user_by_email(email)
    if not user:
        return False
    return verify_password_user_utils(user['id'], password)

def verify_password(password, password_hash):
    """Verify password against hash - fallback method"""
    # This is now a fallback - prefer the user_utils version
    import hashlib
    
    if not password_hash:
        return False
    
    # Simple hash comparison (use bcrypt or similar in production)
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    return hashed_input == password_hash

def hash_password(password):
    """Hash password for storage"""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

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

# API Routes for authentication

def create_auth_routes(app):
    """Create authentication routes"""
    
    @app.route('/auth/admin/login', methods=['POST'])
    def admin_login():
        try:
            data = request.get_json()
            
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({'error': 'Email and password required'}), 400
            
            result = authenticate_admin(data['email'], data['password'])
            
            return jsonify({
                'success': True,
                'token': result['token'],
                'user': result['user']
            }), 200
            
        except AuthError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            logger.error(f"Admin login error: {e}")
            return jsonify({'error': 'Login failed'}), 500
    
    @app.route('/auth/manufacturer/login', methods=['POST'])
    def manufacturer_login():
        try:
            data = request.get_json()
            
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({'error': 'Email and password required'}), 400
            
            result = authenticate_manufacturer(data['email'], data['password'])
            
            return jsonify({
                'success': True,
                'token': result['token'],
                'user': result['user']
            }), 200
            
        except AuthError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            logger.error(f"Manufacturer login error: {e}")
            return jsonify({'error': 'Login failed'}), 500
    
    @app.route('/auth/verify', methods=['GET'])
    @require_auth
    def verify_auth():
        """Verify if token is valid"""
        return jsonify({
            'valid': True,
            'user': request.current_user
        }), 200
    
    @app.route('/auth/logout', methods=['POST'])
    @require_auth
    def logout():
        """Logout (mainly for logging purposes)"""
        try:
            log_security_event('logout', request.current_user['user_id'], request.remote_addr)
            return jsonify({'success': True, 'message': 'Logged out successfully'}), 200
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({'error': 'Logout failed'}), 500