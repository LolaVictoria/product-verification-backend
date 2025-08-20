# Create a test file: test_auth_import.py
# Run this independently to check for import errors

def test_auth_blueprint():
    """Test if auth blueprint can be imported and has routes"""
    try:
        print("Testing auth blueprint import...")
        
        # Test import
        from routes.auth import auth_bp
        print("✓ Successfully imported auth_bp")
        
        # Check blueprint properties
        print(f"Blueprint name: {auth_bp.name}")
        print(f"Blueprint url_prefix: {auth_bp.url_prefix}")
        
        # Check deferred functions (routes)
        print(f"Number of deferred functions: {len(auth_bp.deferred_functions)}")
        
        # List the deferred functions (these are your routes)
        for i, func in enumerate(auth_bp.deferred_functions):
            print(f"  Route {i+1}: {func}")
        
        # Check if signup route is in the functions
        signup_found = False
        for func in auth_bp.deferred_functions:
            if hasattr(func, '__name__') and 'signup' in str(func):
                signup_found = True
                break
        
        print(f"Signup route found: {signup_found}")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Other error: {e}")
        return False

if __name__ == "__main__":
    test_auth_blueprint()