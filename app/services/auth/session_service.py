"""
Session Service
Manages user sessions, login tracking, and session validation
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
import secrets

from app.config.database import get_db_connection
from app.services.auth.token_service import token_service

logger = logging.getLogger(__name__)


class SessionService:
    """Service for managing user sessions"""
    
    def __init__(self):
        self.db = get_db_connection()
        self.sessions_collection = self.db.sessions
        self.session_duration = timedelta(days=7)  # Default session duration
    
    def create_session(self, user_id: str, user_data: Dict, ip_address: str = None, user_agent: str = None) -> Dict:
        """
        Create a new session for user
        
        Args:
            user_id: User's unique ID
            user_data: User information (email, role, etc.)
            ip_address: User's IP address
            user_agent: User's browser/device info
            
        Returns:
            Dict with session info and tokens
        """
        try:
            # Generate session ID
            session_id = secrets.token_urlsafe(32)
            
            # Generate access and refresh tokens
            access_token = token_service.generate_access_token(user_id, user_data)
            refresh_token = token_service.generate_refresh_token(user_id)
            
            # Create session document
            session_doc = {
                'session_id': session_id,
                'user_id': user_id,
                'email': user_data.get('email'),
                'role': user_data.get('role'),
                'refresh_token': refresh_token,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'created_at': datetime.now(timezone.utc),
                'expires_at': datetime.now(timezone.utc) + self.session_duration,
                'last_activity': datetime.now(timezone.utc),
                'is_active': True
            }
            
            # Store session in database
            self.sessions_collection.insert_one(session_doc)
            
            logger.info(f"Session created for user: {user_id}")
            
            return {
                'success': True,
                'session_id': session_id,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': 3600,  # Access token expires in 1 hour
                'user': {
                    'id': user_id,
                    'email': user_data.get('email'),
                    'role': user_data.get('role'),
                    'name': user_data.get('name', '')
                }
            }
            
        except Exception as e:
            logger.error(f"Create session error: {e}")
            return {
                'success': False,
                'error': 'Failed to create session'
            }
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by session ID"""
        try:
            session = self.sessions_collection.find_one({
                'session_id': session_id,
                'is_active': True
            })
            
            if not session:
                return None
            
            # Check if session has expired
            if session['expires_at'] < datetime.now(timezone.utc):
                self.invalidate_session(session_id)
                return None
            
            return session
            
        except Exception as e:
            logger.error(f"Get session error: {e}")
            return None
    
    def get_user_sessions(self, user_id: str, active_only: bool = True) -> list:
        """Get all sessions for a user"""
        try:
            query = {'user_id': user_id}
            if active_only:
                query['is_active'] = True
                query['expires_at'] = {'$gt': datetime.now(timezone.utc)}
            
            sessions = list(self.sessions_collection.find(query).sort('created_at', -1))
            
            # Remove sensitive data
            for session in sessions:
                session.pop('refresh_token', None)
                session.pop('_id', None)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Get user sessions error: {e}")
            return []
    
    def update_session_activity(self, session_id: str) -> bool:
        """Update last activity timestamp for session"""
        try:
            result = self.sessions_collection.update_one(
                {'session_id': session_id, 'is_active': True},
                {'$set': {'last_activity': datetime.now(timezone.utc)}}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Update session activity error: {e}")
            return False
    
    def refresh_session(self, refresh_token: str) -> Dict:
        """
        Refresh session using refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dict with new access token
        """
        try:
            # Verify refresh token
            payload = token_service.verify_token(refresh_token)
            
            if not payload:
                return {
                    'success': False,
                    'error': 'Invalid refresh token'
                }
            
            user_id = payload.get('sub') or payload.get('user_id')
            
            # Find session with this refresh token
            session = self.sessions_collection.find_one({
                'user_id': user_id,
                'refresh_token': refresh_token,
                'is_active': True
            })
            
            if not session:
                return {
                    'success': False,
                    'error': 'Session not found'
                }
            
            # Check if session has expired
            if session['expires_at'] < datetime.now(timezone.utc):
                self.invalidate_session(session['session_id'])
                return {
                    'success': False,
                    'error': 'Session expired'
                }
            
            # Generate new access token
            user_data = {
                'email': session['email'],
                'role': session['role']
            }
            
            new_access_token = token_service.generate_access_token(user_id, user_data)
            
            # Update last activity
            self.update_session_activity(session['session_id'])
            
            logger.info(f"Session refreshed for user: {user_id}")
            
            return {
                'success': True,
                'access_token': new_access_token,
                'expires_in': 3600
            }
            
        except Exception as e:
            logger.error(f"Refresh session error: {e}")
            return {
                'success': False,
                'error': 'Failed to refresh session'
            }
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate/logout a session"""
        try:
            result = self.sessions_collection.update_one(
                {'session_id': session_id},
                {'$set': {
                    'is_active': False,
                    'invalidated_at': datetime.now(timezone.utc)
                }}
            )
            
            if result.modified_count > 0:
                logger.info(f"Session invalidated: {session_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Invalidate session error: {e}")
            return False
    
    def invalidate_user_sessions(self, user_id: str, except_session: str = None) -> int:
        """
        Invalidate all sessions for a user
        
        Args:
            user_id: User's ID
            except_session: Optional session ID to keep active
            
        Returns:
            Number of sessions invalidated
        """
        try:
            query = {
                'user_id': user_id,
                'is_active': True
            }
            
            if except_session:
                query['session_id'] = {'$ne': except_session}
            
            result = self.sessions_collection.update_many(
                query,
                {'$set': {
                    'is_active': False,
                    'invalidated_at': datetime.now(timezone.utc)
                }}
            )
            
            logger.info(f"Invalidated {result.modified_count} sessions for user: {user_id}")
            
            return result.modified_count
            
        except Exception as e:
            logger.error(f"Invalidate user sessions error: {e}")
            return 0
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions (run periodically)"""
        try:
            result = self.sessions_collection.update_many(
                {
                    'expires_at': {'$lt': datetime.now(timezone.utc)},
                    'is_active': True
                },
                {'$set': {
                    'is_active': False,
                    'invalidated_at': datetime.now(timezone.utc)
                }}
            )
            
            if result.modified_count > 0:
                logger.info(f"Cleaned up {result.modified_count} expired sessions")
            
            return result.modified_count
            
        except Exception as e:
            logger.error(f"Cleanup expired sessions error: {e}")
            return 0
    
    def get_session_stats(self, user_id: str) -> Dict:
        """Get session statistics for a user"""
        try:
            total_sessions = self.sessions_collection.count_documents({'user_id': user_id})
            active_sessions = self.sessions_collection.count_documents({
                'user_id': user_id,
                'is_active': True,
                'expires_at': {'$gt': datetime.now(timezone.utc)}
            })
            
            # Get most recent session
            recent_session = self.sessions_collection.find_one(
                {'user_id': user_id},
                sort=[('created_at', -1)]
            )
            
            last_login = recent_session['created_at'] if recent_session else None
            
            return {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'last_login': last_login
            }
            
        except Exception as e:
            logger.error(f"Get session stats error: {e}")
            return {
                'total_sessions': 0,
                'active_sessions': 0,
                'last_login': None
            }
    
    def validate_session_token(self, session_id: str, access_token: str) -> Dict:
        """
        Validate that access token belongs to session
        
        Args:
            session_id: Session ID
            access_token: Access token to validate
            
        Returns:
            Dict with validation result
        """
        try:
            # Get session
            session = self.get_session(session_id)
            
            if not session:
                return {
                    'valid': False,
                    'error': 'Invalid session'
                }
            
            # Verify access token
            payload = token_service.verify_token(access_token)
            
            if not payload:
                return {
                    'valid': False,
                    'error': 'Invalid token'
                }
            
            # Check if token user matches session user
            token_user_id = payload.get('sub') or payload.get('user_id')
            
            if token_user_id != session['user_id']:
                return {
                    'valid': False,
                    'error': 'Token user mismatch'
                }
            
            # Update session activity
            self.update_session_activity(session_id)
            
            return {
                'valid': True,
                'user_id': session['user_id'],
                'email': session['email'],
                'role': session['role']
            }
            
        except Exception as e:
            logger.error(f"Validate session token error: {e}")
            return {
                'valid': False,
                'error': 'Validation failed'
            }


session_service = SessionService()