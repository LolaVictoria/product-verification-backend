# Create core/exceptions.py
class VerificationError(Exception):
    pass

class AuthError(Exception):
    pass

class ValidationError(Exception):
    pass

# Use these instead of generic Exception