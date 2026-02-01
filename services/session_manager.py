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
                    'suspiciousKeywords': []
                },
                'agent_notes': [],
                'created_at': datetime.utcnow().isoformat(),
                'last_updated': datetime.utcnow().isoformat(),
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
            
            message = {
                'sender': sender,
                'text': text,
                'timestamp': timestamp or datetime.utcnow().isoformat()
            }
            
            session['conversation_history'].append(message)
            session['messages_exchanged'] = len(session['conversation_history'])
            session['last_updated'] = datetime.utcnow().isoformat()
            
            return session
    
    def set_scam_detected(
        self,
        session_id: str,
        detected: bool,
        confidence: float,
        category: str
    ) -> Optional[dict]:
        """
        Mark session as scam detected
        
        Args:
            session_id: Session identifier
            detected: Whether scam was detected
            confidence: Detection confidence score
            category: Scam category
            
        Returns:
            Updated session or None
        """
        return self.update_session(session_id, {
            'scam_detected': detected,
            'scam_confidence': confidence,
            'scam_category': category,
            'agent_activated': detected  # Activate agent when scam detected
        })
    
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
            for key in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers', 'suspiciousKeywords']:
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
            'intelligence_count': {
                'bank_accounts': len(session['extracted_intelligence'].get('bankAccounts', [])),
                'upi_ids': len(session['extracted_intelligence'].get('upiIds', [])),
                'phishing_links': len(session['extracted_intelligence'].get('phishingLinks', [])),
                'phone_numbers': len(session['extracted_intelligence'].get('phoneNumbers', [])),
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
