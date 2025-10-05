# services/security_features_service.py 
"""
Advanced security features for customer protection
Duress PIN, counterfeit alerts, emergency notifications
"""
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from app.config.database import get_db_connection
from app.services.notification_service import notification_service
import logging

logger = logging.getLogger(__name__)

class SecurityFeaturesService:
    """Advanced security features for customer protection"""
    
    def __init__(self):
        self.db = get_db_connection()
    
    def setup_duress_pin(self, customer_id: str, regular_pin: str, duress_pin: str) -> Dict[str, Any]:
        """Set up duress PIN for customer emergency situations"""
        try:
            # Validate PINs are different
            if regular_pin == duress_pin:
                return {'success': False, 'error': 'Duress PIN must be different from regular PIN'}
            
            # Hash both PINs
            regular_hash = self._hash_pin(regular_pin)
            duress_hash = self._hash_pin(duress_pin)
            
            # Store in database
            pin_data = {
                'customer_id': customer_id,
                'regular_pin_hash': regular_hash,
                'duress_pin_hash': duress_hash,
                'created_at': datetime.now(timezone.utc),
                'last_used': None,
                'duress_activated_count': 0
            }
            
            # Upsert PIN configuration
            self.db.customer_security.update_one(
                {'customer_id': customer_id},
                {'$set': pin_data},
                upsert=True
            )
            
            return {
                'success': True,
                'message': 'Duress PIN configured successfully',
                'emergency_contacts_needed': True
            }
            
        except Exception as e:
            logger.error(f"Duress PIN setup error: {e}")
            return {'success': False, 'error': 'Failed to setup duress PIN'}
    
    def verify_pin_and_check_duress(self, customer_id: str, entered_pin: str, 
                                  location_data: Dict = None) -> Dict[str, Any]:
        """Verify PIN and detect duress situation"""
        try:
            # Get customer security config
            security_config = self.db.customer_security.find_one({'customer_id': customer_id})
            if not security_config:
                return {'success': False, 'error': 'Security configuration not found'}
            
            entered_hash = self._hash_pin(entered_pin)
            
            # Check if it's the regular PIN
            if entered_hash == security_config['regular_pin_hash']:
                return {
                    'success': True,
                    'pin_verified': True,
                    'duress_detected': False,
                    'message': 'PIN verified successfully'
                }
            
            # Check if it's the duress PIN
            elif entered_hash == security_config['duress_pin_hash']:
                # DURESS DETECTED - Trigger emergency protocols
                duress_response = self._handle_duress_activation(
                    customer_id, location_data, security_config
                )
                
                return {
                    'success': True,  # Don't let attacker know duress was detected
                    'pin_verified': True,  # Act normal to protect customer
                    'duress_detected': True,  # Internal flag
                    'emergency_response': duress_response,
                    'message': 'PIN verified successfully'  # Hide duress from attacker
                }
            
            else:
                return {
                    'success': False,
                    'pin_verified': False,
                    'duress_detected': False,
                    'error': 'Invalid PIN'
                }
                
        except Exception as e:
            logger.error(f"PIN verification error: {e}")
            return {'success': False, 'error': 'PIN verification failed'}
    
    def _handle_duress_activation(self, customer_id: str, location_data: Dict, 
                                security_config: Dict) -> Dict[str, Any]:
        """Handle duress PIN activation - trigger emergency protocols"""
        try:
            # Log duress activation
            duress_log = {
                'customer_id': customer_id,
                'activated_at': datetime.now(timezone.utc),
                'location_data': location_data,
                'ip_address': location_data.get('ip_address') if location_data else None,
                'user_agent': location_data.get('user_agent') if location_data else None,
                'response_actions': []
            }
            
            response_actions = []
            
            # 1. Notify emergency contacts
            emergency_contacts = self._get_emergency_contacts(customer_id)
            for contact in emergency_contacts:
                try:
                    notification_service.send_duress_alert(contact, customer_id, location_data)
                    response_actions.append(f"Emergency contact notified: {contact['type']}")
                except Exception as e:
                    logger.error(f"Failed to notify emergency contact: {e}")
            
            # 2. Alert law enforcement (if configured)
            if security_config.get('auto_alert_law_enforcement'):
                try:
                    self._alert_law_enforcement(customer_id, location_data)
                    response_actions.append("Law enforcement notified")
                except Exception as e:
                    logger.error(f"Law enforcement alert failed: {e}")
            
            # 3. Activate tracking mode
            self._activate_emergency_tracking(customer_id)
            response_actions.append("Emergency tracking activated")
            
            # 4. Create fake "normal" response for attacker
            fake_response = self._generate_fake_normal_response(customer_id)
            
            # Update duress log
            duress_log['response_actions'] = response_actions
            self.db.duress_activations.insert_one(duress_log)
            
            # Update customer security stats
            self.db.customer_security.update_one(
                {'customer_id': customer_id},
                {
                    '$inc': {'duress_activated_count': 1},
                    '$set': {'last_duress_activation': datetime.now(timezone.utc)}
                }
            )
            
            return {
                'emergency_protocols_activated': True,
                'response_actions': response_actions,
                'fake_response_data': fake_response,
                'emergency_tracking': True
            }
            
        except Exception as e:
            logger.error(f"Duress handling error: {e}")
            return {'emergency_protocols_activated': False, 'error': str(e)}
    
    def setup_counterfeit_alerts(self, customer_id: str, alert_preferences: Dict) -> Dict[str, Any]:
        """Set up counterfeit detection alerts for customer"""
        try:
            alert_config = {
                'customer_id': customer_id,
                'email_alerts': alert_preferences.get('email_alerts', True),
                'sms_alerts': alert_preferences.get('sms_alerts', False),
                'push_notifications': alert_preferences.get('push_notifications', True),
                'immediate_alerts': alert_preferences.get('immediate_alerts', True),
                'weekly_summary': alert_preferences.get('weekly_summary', True),
                'alert_threshold': alert_preferences.get('alert_threshold', 'any'), # 'any', 'multiple', 'verified'
                'created_at': datetime.now(timezone.utc)
            }
            
            self.db.alert_preferences.update_one(
                {'customer_id': customer_id},
                {'$set': alert_config},
                upsert=True
            )
            
            return {
                'success': True,
                'message': 'Counterfeit alert preferences saved',
                'config': alert_config
            }
            
        except Exception as e:
            logger.error(f"Counterfeit alerts setup error: {e}")
            return {'success': False, 'error': 'Failed to setup counterfeit alerts'}
    
    def trigger_counterfeit_alert(self, customer_id: str, product_data: Dict, 
                                location_data: Dict = None) -> Dict[str, Any]:
        """Trigger counterfeit product alert to customer"""
        try:
            # Get customer alert preferences
            alert_prefs = self.db.alert_preferences.find_one({'customer_id': customer_id})
            if not alert_prefs:
                # Create default alert preferences
                self.setup_counterfeit_alerts(customer_id, {})
                alert_prefs = {'email_alerts': True, 'immediate_alerts': True}
            
            alert_data = {
                'customer_id': customer_id,
                'product_serial': product_data.get('serial_number'),
                'product_name': product_data.get('name'),
                'detection_method': product_data.get('detection_method', 'verification_check'),
                'confidence_score': product_data.get('counterfeit_confidence', 85),
                'location_data': location_data,
                'detected_at': datetime.now(timezone.utc),
                'alert_sent': False,
                'customer_notified': False
            }
            
            # Store alert record
            alert_result = self.db.counterfeit_alerts.insert_one(alert_data)
            alert_id = str(alert_result.inserted_id)
            
            notifications_sent = []
            
            # Send immediate alerts if configured
            if alert_prefs.get('immediate_alerts'):
                if alert_prefs.get('email_alerts'):
                    try:
                        notification_service.send_counterfeit_email_alert(
                            customer_id, product_data, location_data, alert_id
                        )
                        notifications_sent.append('email')
                    except Exception as e:
                        logger.error(f"Email alert failed: {e}")
                
                if alert_prefs.get('sms_alerts'):
                    try:
                        notification_service.send_counterfeit_sms_alert(
                            customer_id, product_data, alert_id
                        )
                        notifications_sent.append('sms')
                    except Exception as e:
                        logger.error(f"SMS alert failed: {e}")
                
                if alert_prefs.get('push_notifications'):
                    try:
                        notification_service.send_counterfeit_push_notification(
                            customer_id, product_data, alert_id
                        )
                        notifications_sent.append('push')
                    except Exception as e:
                        logger.error(f"Push notification failed: {e}")
            
            # Update alert record
            self.db.counterfeit_alerts.update_one(
                {'_id': alert_result.inserted_id},
                {
                    '$set': {
                        'alert_sent': len(notifications_sent) > 0,
                        'notifications_sent': notifications_sent,
                        'customer_notified': True
                    }
                }
            )
            
            return {
                'success': True,
                'alert_id': alert_id,
                'notifications_sent': notifications_sent,
                'message': 'Counterfeit alert triggered successfully'
            }
            
        except Exception as e:
            logger.error(f"Counterfeit alert error: {e}")
            return {'success': False, 'error': 'Failed to trigger counterfeit alert'}
    
    def _hash_pin(self, pin: str) -> str:
        """Hash PIN securely"""
        salt = secrets.token_bytes(32)
        pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000)
        return salt.hex() + pin_hash.hex()
    
    def _verify_pin_hash(self, pin: str, stored_hash: str) -> bool:
        """Verify PIN against stored hash"""
        try:
            salt = bytes.fromhex(stored_hash[:64])
            stored_pin_hash = stored_hash[64:]
            pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000)
            return pin_hash.hex() == stored_pin_hash
        except Exception:
            return False

# Add to existing notification_service.py
class NotificationService:
    # ... existing methods ...
    
    def send_duress_alert(self, contact_info: Dict, customer_id: str, location_data: Dict):
        """Send duress/emergency alert to emergency contact"""
        alert_message = f"""
        EMERGENCY ALERT - DURESS SITUATION DETECTED
        
        Customer ID: {customer_id}
        Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        Location: {location_data.get('city', 'Unknown')}, {location_data.get('state', 'Unknown')}
        
        This is an automated alert from the Product Verification System.
        A duress PIN was used, indicating a potential emergency situation.
        
        If this is a false alarm, please contact support immediately.
        """
        
        if contact_info['type'] == 'email':
            self.send_email(contact_info['value'], "EMERGENCY DURESS ALERT", alert_message)
        elif contact_info['type'] == 'sms':
            self.send_sms(contact_info['value'], alert_message)

# security_features_service singleton
security_features_service = SecurityFeaturesService()