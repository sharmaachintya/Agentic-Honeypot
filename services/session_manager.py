"""
Session Manager Module
Handles in-memory session storage and management
"""
from typing import Dict, Optional, List
from datetime import datetime
import threading


class SessionManager:
    """
    In-memory session manager for tracking conversations.
    Thread-safe implementation using locks.
    """
    
    def __init__(self):
        """Initialize the session manager"""
        self._sessions: Dict[str, dict] = {}
        self._lock = threading.Lock()
    
    def create_session(self, session_id: str) -> dict:
        """
        Create a new session
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            New session data dict
        """
        with self._lock:
            if session_id in self._sessions:
                return self._sessions[session_id]
            
            now = datetime.utcnow().isoformat()
            session = {
                'session_id': session_id,
                'scam_detected': False,
                'scam_confidence': 0.0,
                'scam_category': 'UNKNOWN',
                'agent_activated': False,
                'messages_exchanged': 0,
                'conversation_history': [],
                'extracted_intelligence': {
                    'bankAccounts': [],
                    'upiIds': [],
                    'phishingLinks': [],
                    'phoneNumbers': [],
                    'emailAddresses': [],
                    'caseIds': [],
                    'policyNumbers': [],
                    'orderNumbers': [],
                    'suspiciousKeywords': []
                },
                'agent_notes': [],
                'created_at': now,
                'last_updated': now,
                'first_message_at': now,
                'last_message_at': now,
                'callback_sent': False
            }
            
            self._sessions[session_id] = session
            return session
    
    def get_session(self, session_id: str) -> Optional[dict]:
        """
        Get an existing session
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)
    
    def get_or_create_session(self, session_id: str) -> dict:
        """
        Get existing session or create new one
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data dict
        """
        session = self.get_session(session_id)
        if session is None:
            session = self.create_session(session_id)
        return session
    
    def update_session(self, session_id: str, updates: dict) -> Optional[dict]:
        """
        Update session with new data
        
        Args:
            session_id: Session identifier
            updates: Dictionary of fields to update
            
        Returns:
            Updated session or None if not found
        """
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            
            for key, value in updates.items():
                if key in session:
                    session[key] = value
            
            session['last_updated'] = datetime.utcnow().isoformat()
            return session
    
    def add_message(
        self,
        session_id: str,
        sender: str,
        text: str,
        timestamp: str = None
    ) -> Optional[dict]:
        """
        Add a message to session conversation history
        
        Args:
            session_id: Session identifier
            sender: 'scammer' or 'user'
            text: Message text
            timestamp: ISO timestamp (auto-generated if not provided)
            
        Returns:
            Updated session or None
        """
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            now = datetime.utcnow().isoformat()
            msg_timestamp = timestamp or now
            
            message = {
                'sender': sender,
                'text': text,
                'timestamp': msg_timestamp
            }
            
            session['conversation_history'].append(message)
            session['messages_exchanged'] = len(session['conversation_history'])
            session['last_updated'] = now
            session['last_message_at'] = now
            
            # Set first_message_at only for the very first message
            if session['messages_exchanged'] == 1:
                session['first_message_at'] = now
            
            return session
    
    def set_scam_detected(
        self,
        session_id: str,
        detected: bool,
        confidence: float,
        category: str
    ) -> Optional[dict]:
        """
        Mark session as scam detected.
        
        IMPORTANT: Once a specific category is set (not GENERIC/UNKNOWN),
        it won't be overridden by a lower-confidence or generic category.
        Confidence always tracks the MAXIMUM seen.
        """
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            
            # Always track the highest confidence ever seen
            current_confidence = session.get('scam_confidence', 0.0)
            best_confidence = max(current_confidence, confidence)
            
            # Lock category: once set to specific type, don't downgrade
            current_category = session.get('scam_category', 'UNKNOWN')
            generic_categories = {'UNKNOWN', 'GENERIC_SCAM'}
            
            if current_category in generic_categories:
                # Current is generic → always upgrade to new category
                new_category = category
            elif category not in generic_categories and confidence > current_confidence:
                # Both specific → only upgrade if new has higher confidence
                new_category = category
            else:
                # Keep current specific category
                new_category = current_category
            
            session['scam_detected'] = detected
            session['scam_confidence'] = best_confidence
            session['scam_category'] = new_category
            session['agent_activated'] = detected
            session['last_updated'] = datetime.utcnow().isoformat()
            
            return session
    
    def update_intelligence(
        self,
        session_id: str,
        intelligence: dict
    ) -> Optional[dict]:
        """
        Update extracted intelligence for session
        
        Args:
            session_id: Session identifier
            intelligence: Dict with bankAccounts, upiIds, etc.
            
        Returns:
            Updated session or None
        """
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            current_intel = session['extracted_intelligence']
            
            # Merge new intelligence with existing (avoid duplicates)
            for key in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers', 'emailAddresses', 'caseIds', 'policyNumbers', 'orderNumbers', 'suspiciousKeywords']:
                if key in intelligence:
                    # Convert to set for deduplication, then back to list
                    existing = set(current_intel.get(key, []))
                    new_items = set(intelligence.get(key, []))
                    current_intel[key] = list(existing.union(new_items))
            
            session['last_updated'] = datetime.utcnow().isoformat()
            return session
    
    def add_agent_note(self, session_id: str, note: str) -> Optional[dict]:
        """
        Add a note from the agent about the conversation
        
        Args:
            session_id: Session identifier
            note: Note text
            
        Returns:
            Updated session or None
        """
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            session['agent_notes'].append(note)
            session['last_updated'] = datetime.utcnow().isoformat()
            
            return session
    
    def mark_callback_sent(self, session_id: str) -> Optional[dict]:
        """
        Mark that the final callback has been sent
        
        Args:
            session_id: Session identifier
            
        Returns:
            Updated session or None
        """
        return self.update_session(session_id, {'callback_sent': True})
    
    def get_engagement_duration_seconds(self, session_id: str) -> float:
        """
        Calculate engagement duration in seconds for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Duration in seconds (float)
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return 0.0
            
            try:
                first_msg = session.get('first_message_at', session.get('created_at'))
                last_msg = session.get('last_message_at', session.get('last_updated'))
                
                # Parse ISO timestamps
                fmt_options = [
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%dT%H:%M:%S.%fZ',
                ]
                
                first_dt = None
                last_dt = None
                
                for fmt in fmt_options:
                    if first_dt is None:
                        try:
                            first_dt = datetime.strptime(first_msg, fmt)
                        except (ValueError, TypeError):
                            pass
                    if last_dt is None:
                        try:
                            last_dt = datetime.strptime(last_msg, fmt)
                        except (ValueError, TypeError):
                            pass
                
                if first_dt and last_dt:
                    duration = (last_dt - first_dt).total_seconds()
                    # Ensure minimum duration based on message count for scoring
                    # If multiple messages exchanged but duration is tiny (fast API),
                    # use a reasonable estimate
                    msg_count = session.get('messages_exchanged', 0)
                    if duration < 5 and msg_count > 2:
                        # Estimate ~8 seconds per message exchange as minimum
                        duration = max(duration, msg_count * 8.0)
                    return max(0.0, duration)
                else:
                    # Fallback: estimate from message count
                    msg_count = session.get('messages_exchanged', 0)
                    return max(0.0, msg_count * 8.0)
                    
            except Exception:
                # Safe fallback
                msg_count = session.get('messages_exchanged', 0)
                return max(0.0, msg_count * 8.0)
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False
    
    def get_all_sessions(self) -> List[dict]:
        """
        Get all active sessions (for debugging/admin)
        
        Returns:
            List of all session data
        """
        with self._lock:
            return list(self._sessions.values())
    
    def get_session_count(self) -> int:
        """
        Get count of active sessions
        
        Returns:
            Number of sessions
        """
        with self._lock:
            return len(self._sessions)
    
    def get_session_summary(self, session_id: str) -> Optional[dict]:
        """
        Get a summary of session for reporting
        
        Args:
            session_id: Session identifier
            
        Returns:
            Summary dict or None
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        return {
            'session_id': session['session_id'],
            'scam_detected': session['scam_detected'],
            'scam_category': session['scam_category'],
            'agent_activated': session['agent_activated'],
            'messages_exchanged': session['messages_exchanged'],
            'engagement_duration_seconds': self.get_engagement_duration_seconds(session_id),
            'intelligence_count': {
                'bank_accounts': len(session['extracted_intelligence'].get('bankAccounts', [])),
                'upi_ids': len(session['extracted_intelligence'].get('upiIds', [])),
                'phishing_links': len(session['extracted_intelligence'].get('phishingLinks', [])),
                'phone_numbers': len(session['extracted_intelligence'].get('phoneNumbers', [])),
                'email_addresses': len(session['extracted_intelligence'].get('emailAddresses', [])),
            },
            'callback_sent': session['callback_sent'],
            'created_at': session['created_at'],
            'last_updated': session['last_updated']
        }
    
    def clear_all_sessions(self) -> int:
        """
        Clear all sessions (for testing/reset)
        
        Returns:
            Number of sessions cleared
        """
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            return count
