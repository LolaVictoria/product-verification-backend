"""
Webhook Validation
Validates webhook signatures and payloads
"""
import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)


class WebhookValidator:
    """Validates webhook signatures and payloads"""
    
    @staticmethod
    def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify webhook signature using HMAC SHA256
        
        Args:
            payload: Raw webhook payload bytes
            signature: Signature from webhook header
            secret: Webhook secret key
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not signature or not secret:
            logger.warning("Missing signature or secret for webhook verification")
            return False
        
        try:
            # Remove 'sha256=' prefix if present
            if signature.startswith('sha256='):
                signature = signature[7:]
            
            # Calculate expected signature
            expected = hmac.new(
                secret.encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Use constant-time comparison to prevent timing attacks
            is_valid = hmac.compare_digest(expected, signature)
            
            if not is_valid:
                logger.warning("Webhook signature verification failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Webhook signature verification error: {e}")
            return False
    
    @staticmethod
    def verify_stripe_signature(payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify Stripe webhook signature (uses same logic as verify_signature)
        
        Args:
            payload: Raw webhook payload bytes
            signature: Stripe-Signature header value
            secret: Stripe webhook secret
            
        Returns:
            True if signature is valid, False otherwise
        """
        return WebhookValidator.verify_signature(payload, signature, secret)
    
    @staticmethod
    def validate_blockchain_event(data: dict) -> bool:
        """
        Validate blockchain event payload structure
        
        Args:
            data: Blockchain event data
            
        Returns:
            True if payload is valid, False otherwise
        """
        required_fields = ['event_type', 'transaction_hash', 'block_number']
        
        is_valid = all(field in data for field in required_fields)
        
        if not is_valid:
            missing = [f for f in required_fields if f not in data]
            logger.warning(f"Invalid blockchain event - missing fields: {missing}")
        
        return is_valid
    
    @staticmethod
    def validate_verification_event(data: dict) -> bool:
        """
        Validate verification event payload structure
        
        Args:
            data: Verification event data
            
        Returns:
            True if payload is valid, False otherwise
        """
        required_fields = ['serial_number', 'timestamp', 'result']
        
        is_valid = all(field in data for field in required_fields)
        
        if not is_valid:
            missing = [f for f in required_fields if f not in data]
            logger.warning(f"Invalid verification event - missing fields: {missing}")
        
        return is_valid
    
    @staticmethod
    def validate_manufacturer_notification(data: dict) -> bool:
        """
        Validate manufacturer notification payload
        
        Args:
            data: Notification data
            
        Returns:
            True if payload is valid, False otherwise
        """
        required_fields = ['type', 'manufacturer_id']
        
        is_valid = all(field in data for field in required_fields)
        
        if not is_valid:
            missing = [f for f in required_fields if f not in data]
            logger.warning(f"Invalid manufacturer notification - missing fields: {missing}")
        
        return is_valid


webhook_validator = WebhookValidator()