"""
Callback Service Module
Handles sending final results to GUVI evaluation endpoint
"""
import requests
import logging
from typing import Dict, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CallbackService:
    """
    Service for sending final intelligence results to GUVI evaluation endpoint.
    This is mandatory for scoring in the hackathon.
    """
    
    # GUVI evaluation endpoint
    GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    # Timeout for API calls
    TIMEOUT = 10
    
    def __init__(self):
        """Initialize the callback service"""
        self.last_callback_response = None
        self.callback_history = []
    
    def send_final_result(
        self,
        session_id: str,
        scam_detected: bool,
        total_messages: int,
        extracted_intelligence: Dict,
        agent_notes: str
    ) -> Dict:
        """
        Send final result to GUVI evaluation endpoint
        
        Args:
            session_id: Unique session identifier
            scam_detected: Whether scam was confirmed
            total_messages: Total messages exchanged in session
            extracted_intelligence: Dict with bankAccounts, upiIds, etc.
            agent_notes: Summary of scammer behavior
            
        Returns:
            Response dict with status and details
        """
        # Prepare payload according to GUVI specification
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": {
                "bankAccounts": extracted_intelligence.get("bankAccounts", []),
                "upiIds": extracted_intelligence.get("upiIds", []),
                "phishingLinks": extracted_intelligence.get("phishingLinks", []),
                "phoneNumbers": extracted_intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": extracted_intelligence.get("suspiciousKeywords", [])
            },
            "agentNotes": agent_notes
        }
        
        logger.info(f"Sending callback for session {session_id}")
        logger.info(f"Payload: {payload}")
        
        try:
            response = requests.post(
                self.GUVI_ENDPOINT,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.TIMEOUT
            )
            
            # Store response for debugging
            self.last_callback_response = {
                "status_code": response.status_code,
                "response_text": response.text,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Log the callback
            self.callback_history.append({
                "session_id": session_id,
                "payload": payload,
                "response": self.last_callback_response,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            if response.status_code == 200:
                logger.info(f"Callback successful for session {session_id}")
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "message": "Callback sent successfully",
                    "response": response.json() if response.text else None
                }
            else:
                logger.warning(f"Callback returned non-200 status: {response.status_code}")
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "message": f"Callback returned status {response.status_code}",
                    "response": response.text
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"Callback timeout for session {session_id}")
            return {
                "success": False,
                "status_code": None,
                "message": "Callback request timed out",
                "error": "timeout"
            }
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for callback: {str(e)}")
            return {
                "success": False,
                "status_code": None,
                "message": "Connection error",
                "error": str(e)
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception for callback: {str(e)}")
            return {
                "success": False,
                "status_code": None,
                "message": "Request failed",
                "error": str(e)
            }
    
    def should_send_callback(
        self,
        session: Dict,
        min_messages: int = 3,
        require_intelligence: bool = True
    ) -> bool:
        """
        Determine if callback should be sent for this session
        
        Args:
            session: Session data dict
            min_messages: Minimum messages before sending callback
            require_intelligence: Whether to require extracted intelligence
            
        Returns:
            True if callback should be sent
        """
        # Don't send if already sent
        if session.get('callback_sent', False):
            return False
        
        # Must have scam detected
        if not session.get('scam_detected', False):
            return False
        
        # Check minimum messages exchanged
        messages = session.get('messages_exchanged', 0)
        if messages < min_messages:
            return False
        
        # Check if we have meaningful intelligence
        if require_intelligence:
            intel = session.get('extracted_intelligence', {})
            has_intel = (
                len(intel.get('bankAccounts', [])) > 0 or
                len(intel.get('upiIds', [])) > 0 or
                len(intel.get('phishingLinks', [])) > 0 or
                len(intel.get('phoneNumbers', [])) > 0 or
                len(intel.get('suspiciousKeywords', [])) >= 3
            )
            if not has_intel:
                return False
        
        return True
    
    def prepare_agent_notes(self, session: Dict) -> str:
        """
        Prepare agent notes summary from session data
        
        Args:
            session: Session data dict
            
        Returns:
            Formatted agent notes string
        """
        notes = session.get('agent_notes', [])
        category = session.get('scam_category', 'UNKNOWN')
        confidence = session.get('scam_confidence', 0)
        messages = session.get('messages_exchanged', 0)
        
        # Build summary
        summary_parts = []
        
        # Add scam category
        summary_parts.append(f"Scam type: {category}")
        
        # Add confidence
        summary_parts.append(f"Detection confidence: {confidence*100:.0f}%")
        
        # Add engagement summary
        summary_parts.append(f"Messages exchanged: {messages}")
        
        # Add collected notes
        if notes:
            summary_parts.append(f"Observations: {'; '.join(notes[:5])}")
        
        # Analyze tactics used
        intel = session.get('extracted_intelligence', {})
        tactics = []
        
        keywords = intel.get('suspiciousKeywords', [])
        if any(k in keywords for k in ['urgent', 'immediately', 'now', 'today']):
            tactics.append("urgency tactics")
        if any(k in keywords for k in ['blocked', 'suspended', 'penalty']):
            tactics.append("threat tactics")
        if any(k in keywords for k in ['upi', 'bank', 'transfer', 'payment']):
            tactics.append("payment redirection")
        if any(k in keywords for k in ['verify', 'kyc', 'update']):
            tactics.append("verification pretexting")
        if any(k in keywords for k in ['prize', 'winner', 'cashback', 'refund']):
            tactics.append("reward baiting")
        
        if tactics:
            summary_parts.append(f"Tactics used: {', '.join(tactics)}")
        
        return ". ".join(summary_parts)
    
    def get_callback_history(self) -> list:
        """
        Get history of callbacks sent
        
        Returns:
            List of callback records
        """
        return self.callback_history
    
    def get_last_callback(self) -> Optional[Dict]:
        """
        Get the last callback response
        
        Returns:
            Last callback response dict or None
        """
        return self.last_callback_response
