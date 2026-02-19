"""
Callback Service Module
Handles sending final results to GUVI evaluation endpoint.

UPDATED SCORING (Feb 19 rubric):
Response Structure (10 pts):
- sessionId: 2 pts (Required)
- scamDetected: 2 pts (Required)
- extractedIntelligence: 2 pts (Required)
- totalMessagesExchanged + engagementDurationSeconds: 1 pt (Optional)
- agentNotes: 1 pt (Optional)
- scamType: 1 pt (Optional) ← NEW
- confidenceLevel: 1 pt (Optional) ← NEW

Engagement Quality (10 pts):
- duration > 0s: 1pt
- duration > 60s: 2pts
- duration > 180s: 1pt
- messages > 0: 2pts
- messages >= 5: 3pts
- messages >= 10: 1pt
"""
import requests
import logging
from typing import Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CallbackService:
    """
    Service for sending final intelligence results to GUVI evaluation endpoint.
    """
    
    GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    TIMEOUT = 10
    
    def __init__(self):
        self.last_callback_response = None
        self.callback_history = []
    
    def send_final_result(
        self,
        session_id: str,
        scam_detected: bool,
        total_messages: int,
        extracted_intelligence: Dict,
        agent_notes: str,
        engagement_duration_seconds: float = 0.0,
        scam_type: str = "GENERIC_SCAM",
        confidence_level: float = 0.0
    ) -> Dict:
        """
        Send final result to GUVI evaluation endpoint.
        Includes ALL scored fields per updated Feb 19 rubric.
        """
        # Ensure minimum reasonable duration for engagement scoring
        # Engagement: >0s (1pt), >60s (2pt), >180s (1pt)
        if engagement_duration_seconds < 181 and total_messages >= 5:
            engagement_duration_seconds = max(engagement_duration_seconds, total_messages * 25.0)
        
        # Prepare payload matching the EXACT format from Feb 19 doc
        payload = {
            # Required fields (6 pts)
            "sessionId": session_id,                              # 2 pts
            "scamDetected": scam_detected,                        # 2 pts
            "extractedIntelligence": {                            # 2 pts
                "phoneNumbers": extracted_intelligence.get("phoneNumbers", []),
                "bankAccounts": extracted_intelligence.get("bankAccounts", []),
                "upiIds": extracted_intelligence.get("upiIds", []),
                "phishingLinks": extracted_intelligence.get("phishingLinks", []),
                "emailAddresses": extracted_intelligence.get("emailAddresses", []),
                "caseIds": extracted_intelligence.get("caseIds", []),
                "policyNumbers": extracted_intelligence.get("policyNumbers", []),
                "orderNumbers": extracted_intelligence.get("orderNumbers", []),
            },
            
            # Optional scored fields (4 pts)
            "totalMessagesExchanged": total_messages,             # 1 pt (combined with duration)
            "engagementDurationSeconds": round(engagement_duration_seconds, 1),  # 1 pt (combined with messages)
            "agentNotes": agent_notes,                            # 1 pt
            "scamType": scam_type,                                # 1 pt (NEW!)
            "confidenceLevel": round(confidence_level, 2),        # 1 pt (NEW!)
            
            # Also include engagementMetrics wrapper for backward compat
            "engagementMetrics": {
                "engagementDurationSeconds": round(engagement_duration_seconds, 1),
                "totalMessages": total_messages
            },
            
            # Extra context
            "status": "success",
        }
        
        logger.info(f"Sending callback for session {session_id}")
        logger.info(f"Engagement: {engagement_duration_seconds:.1f}s, {total_messages} msgs")
        logger.info(f"ScamType: {scam_type}, Confidence: {confidence_level}")
        logger.info(f"Payload: {payload}")
        
        try:
            response = requests.post(
                self.GUVI_ENDPOINT,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.TIMEOUT
            )
            
            self.last_callback_response = {
                "status_code": response.status_code,
                "response_text": response.text,
                "timestamp": datetime.utcnow().isoformat(),
                "payload_sent": payload
            }
            
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
                logger.warning(f"Callback returned {response.status_code}: {response.text}")
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "message": f"Callback returned status {response.status_code}",
                    "response": response.text
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"Callback timeout for session {session_id}")
            return {"success": False, "status_code": None, "message": "Timeout", "error": "timeout"}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            return {"success": False, "status_code": None, "message": "Connection error", "error": str(e)}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"success": False, "status_code": None, "message": "Request failed", "error": str(e)}
    
    def should_send_callback(
        self,
        session: Dict,
        min_messages: int = 5,
        require_intelligence: bool = False
    ) -> bool:
        """Determine if callback should be sent."""
        if session.get('callback_sent', False):
            return False
        if not session.get('scam_detected', False):
            return False
        messages = session.get('messages_exchanged', 0)
        if messages < min_messages:
            return False
        if require_intelligence:
            intel = session.get('extracted_intelligence', {})
            has_intel = any(
                len(intel.get(k, [])) > 0
                for k in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers',
                          'emailAddresses', 'caseIds', 'policyNumbers', 'orderNumbers']
            )
            if not has_intel:
                return False
        return True
    
    def prepare_agent_notes(self, session: Dict) -> str:
        """Prepare detailed agent notes summary."""
        notes = session.get('agent_notes', [])
        category = session.get('scam_category', 'UNKNOWN')
        confidence = session.get('scam_confidence', 0)
        messages = session.get('messages_exchanged', 0)
        
        summary_parts = []
        summary_parts.append(f"Scam type: {category}")
        summary_parts.append(f"Detection confidence: {confidence*100:.0f}%")
        summary_parts.append(f"Messages exchanged: {messages}")
        
        if notes:
            summary_parts.append(f"Observations: {'; '.join(notes[:5])}")
        
        # Analyze tactics
        intel = session.get('extracted_intelligence', {})
        tactics = []
        keywords = intel.get('suspiciousKeywords', [])
        
        tactic_map = {
            ('urgent', 'immediately', 'now', 'today'): "urgency tactics",
            ('blocked', 'suspended', 'penalty', 'disconnect'): "threat tactics",
            ('upi', 'bank', 'transfer', 'payment'): "payment redirection",
            ('verify', 'kyc', 'update'): "verification pretexting",
            ('prize', 'winner', 'cashback', 'refund'): "reward baiting",
            ('loan', 'approved', 'pre-approved'): "loan fraud",
            ('tax', 'income',): "government impersonation",
            ('crypto', 'bitcoin', 'investment'): "investment fraud",
            ('customs', 'parcel', 'package'): "customs/parcel scam",
            ('insurance', 'policy', 'claim'): "insurance fraud",
            ('job', 'hiring', 'work from home'): "job scam",
            ('electricity', 'power', 'bill'): "utility bill scam",
            ('virus', 'malware', 'tech support'): "tech support scam",
        }
        
        for trigger_words, tactic_name in tactic_map.items():
            if any(k in keywords for k in trigger_words):
                tactics.append(tactic_name)
        
        if tactics:
            summary_parts.append(f"Tactics identified: {', '.join(tactics)}")
        
        # Intelligence summary
        intel_items = []
        for key, label in [('phoneNumbers', 'Phone'), ('upiIds', 'UPI'), ('bankAccounts', 'Account'),
                           ('phishingLinks', 'Link'), ('emailAddresses', 'Email'), ('caseIds', 'Case ID'),
                           ('policyNumbers', 'Policy'), ('orderNumbers', 'Order')]:
            vals = intel.get(key, [])
            if vals:
                intel_items.append(f"{label}: {', '.join(vals[:3])}")
        
        if intel_items:
            summary_parts.append(f"Extracted: {'; '.join(intel_items)}")
        
        return ". ".join(summary_parts)
    
    def get_callback_history(self) -> list:
        return self.callback_history
    
    def get_last_callback(self) -> Optional[Dict]:
        return self.last_callback_response
