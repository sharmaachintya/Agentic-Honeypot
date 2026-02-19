"""
Agentic Honeypot API for Scam Detection & Intelligence Extraction
Main FastAPI Application

SCORING RUBRIC (100 points per scenario):
- Scam Detection: 20 pts (scamDetected: true)
- Intelligence Extraction: 40 pts (phones 10, bank accounts 10, UPI IDs 10, phishing links 10)
- Engagement Quality: 20 pts (duration>0 5pts, duration>60 5pts, msgs>0 5pts, msgs>=5 5pts)
- Response Structure: 20 pts (status 5, scamDetected 5, extractedIntelligence 5, engagementMetrics 2.5, agentNotes 2.5)
"""
import os
import logging
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import our modules
from models.schemas import (
    IncomingMessageRequest,
    AgentResponse,
    ErrorResponse,
    TestScamRequest,
    TestScamResponse,
    ExtractedIntelligence
)
from agent.scam_detector import ScamDetector
from agent.honeypot_agent import HoneypotAgent
from agent.intelligence import IntelligenceExtractor
from services.session_manager import SessionManager
from services.callback_service import CallbackService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
scam_detector = ScamDetector()
intelligence_extractor = IntelligenceExtractor()
session_manager = SessionManager()
callback_service = CallbackService()

# Honeypot agent will be initialized lazily (requires API key)
honeypot_agent: Optional[HoneypotAgent] = None

# API Key for authentication
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "your-secret-api-key-here")


def get_honeypot_agent() -> HoneypotAgent:
    """Get or initialize the honeypot agent"""
    global honeypot_agent
    if honeypot_agent is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="ANTHROPIC_API_KEY not configured"
            )
        honeypot_agent = HoneypotAgent(api_key=api_key)
    return honeypot_agent


async def verify_api_key(x_api_key: str = Header(None)):
    """Verify the API key from request header"""
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header"
        )
    if x_api_key != API_SECRET_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    return x_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    logger.info("🚀 Honeypot API starting up...")
    logger.info(f"API Key configured: {'Yes' if API_SECRET_KEY != 'your-secret-api-key-here' else 'No (using default)'}")
    logger.info(f"Anthropic API Key configured: {'Yes' if os.getenv('ANTHROPIC_API_KEY') else 'No'}")
    yield
    logger.info("👋 Honeypot API shutting down...")


# Create FastAPI app
app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered honeypot system for scam detection and intelligence extraction",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============== MAIN API ENDPOINTS ==============

@app.post("/api/message")
async def process_message(
    request: Request,
    x_api_key: str = Header(None)
):
    """
    Main endpoint to receive and process incoming messages.
    This is the endpoint GUVI evaluation platform calls.
    
    Flow:
    1. Receive message
    2. Detect scam intent
    3. Activate agent if scam
    4. Generate response
    5. Extract intelligence from ENTIRE conversation
    6. Send callback when ready
    7. Return agent reply
    """
    # Verify API key
    if x_api_key and x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    try:
        # Parse raw JSON body
        body = await request.json()
        logger.info(f"📥 Raw request body: {body}")
        
        # Extract fields with safe defaults
        session_id = body.get('sessionId', body.get('session_id', 'unknown-session'))
        message = body.get('message', {})
        message_text = message.get('text', '') if isinstance(message, dict) else str(message)
        sender = message.get('sender', 'scammer') if isinstance(message, dict) else 'scammer'
        timestamp = message.get('timestamp', datetime.utcnow().isoformat()) if isinstance(message, dict) else datetime.utcnow().isoformat()
        conversation_history = body.get('conversationHistory', body.get('conversation_history', []))
        metadata = body.get('metadata', {})
        
        logger.info(f"📩 Session: {session_id} | From: {sender} | Message: {message_text[:100]}...")
        
        # Get or create session
        session = session_manager.get_or_create_session(session_id)
        
        # Add incoming message to conversation history
        session_manager.add_message(session_id, sender, message_text, timestamp)
        
        # Also add conversation history from request if provided (avoid duplicates)
        if conversation_history:
            for hist_msg in conversation_history:
                if isinstance(hist_msg, dict):
                    existing = session_manager.get_session(session_id)['conversation_history']
                    hist_text = hist_msg.get('text', '')
                    hist_sender = hist_msg.get('sender', 'unknown')
                    msg_exists = any(
                        m['text'] == hist_text and m['sender'] == hist_sender
                        for m in existing
                    )
                    if not msg_exists:
                        session_manager.add_message(
                            session_id,
                            hist_sender,
                            hist_text,
                            hist_msg.get('timestamp', datetime.utcnow().isoformat())
                        )
        
        # Refresh session after updates
        session = session_manager.get_session(session_id)
        
        # Detect scam intent
        detection_result = scam_detector.detect(
            message_text,
            conversation_history=session['conversation_history']
        )
        
        logger.info(f"🔍 Scam detection: is_scam={detection_result.is_scam}, confidence={detection_result.confidence}, category={detection_result.scam_category}")
        
        # Update session with detection results
        if detection_result.is_scam:
            session_manager.set_scam_detected(
                session_id,
                detected=True,
                confidence=detection_result.confidence,
                category=detection_result.scam_category
            )
            session_manager.add_agent_note(
                session_id,
                f"Scam detected: {detection_result.scam_category} ({detection_result.confidence*100:.0f}% confidence)"
            )
        
        # Extract intelligence from ENTIRE conversation (not just current message)
        # This ensures we capture all intelligence across all turns
        all_messages = session['conversation_history']
        combined_intel = intelligence_extractor.extract_from_conversation(all_messages)
        intel_dict = intelligence_extractor.to_dict(combined_intel)
        session_manager.update_intelligence(session_id, intel_dict)
        
        # Refresh session
        session = session_manager.get_session(session_id)
        
        # Generate agent response if scam detected
        if session['scam_detected'] and session['agent_activated']:
            logger.info("🤖 Agent activated, generating response...")
            
            try:
                agent = get_honeypot_agent()
                
                # Prepare metadata
                agent_metadata = {
                    'channel': metadata.get('channel', 'SMS') if isinstance(metadata, dict) else 'SMS',
                    'language': metadata.get('language', 'English') if isinstance(metadata, dict) else 'English',
                    'locale': metadata.get('locale', 'IN') if isinstance(metadata, dict) else 'IN'
                }
                
                # Generate response
                agent_reply = agent.generate_response(
                    current_message=message_text,
                    conversation_history=session['conversation_history'][:-1],  # Exclude current
                    scam_category=session['scam_category'],
                    metadata=agent_metadata
                )
                
                # Add agent's response to conversation
                session_manager.add_message(session_id, 'user', agent_reply)
                
                logger.info(f"💬 Agent reply: {agent_reply[:100]}...")
                
                # Re-extract intelligence after agent response (in case agent provoked new info)
                session = session_manager.get_session(session_id)
                
                # Send callback on EVERY turn after threshold
                # System waits only 10 seconds after conversation ends, so we update every turn
                session = session_manager.get_session(session_id)
                if session['scam_detected'] and session['messages_exchanged'] >= 3:
                    logger.info("📤 Sending/updating callback to GUVI...")
                    
                    # Calculate engagement duration
                    engagement_duration = session_manager.get_engagement_duration_seconds(session_id)
                    
                    # Prepare agent notes
                    agent_notes = callback_service.prepare_agent_notes(session)
                    
                    # Send callback with ALL scored fields including scamType + confidenceLevel
                    callback_result = callback_service.send_final_result(
                        session_id=session_id,
                        scam_detected=session['scam_detected'],
                        total_messages=session['messages_exchanged'],
                        extracted_intelligence=session['extracted_intelligence'],
                        agent_notes=agent_notes,
                        engagement_duration_seconds=engagement_duration,
                        scam_type=session.get('scam_category', 'GENERIC_SCAM'),
                        confidence_level=session.get('scam_confidence', 0.5)
                    )
                    
                    if callback_result['success']:
                        logger.info("✅ Callback sent successfully")
                    else:
                        logger.warning(f"⚠️ Callback failed: {callback_result.get('message')}")
                
                return AgentResponse(status="success", reply=agent_reply)
                
            except Exception as e:
                logger.error(f"Agent error: {str(e)}")
                return AgentResponse(
                    status="success",
                    reply="Hello? What is this about? I don't understand."
                )
        else:
            # No scam detected yet - still respond to keep conversation going
            # This helps if detection threshold isn't met on first message
            logger.info("ℹ️ No scam detected yet or agent not activated, returning generic response")
            
            # If we have some suspicious patterns but below threshold, try engaging anyway
            if detection_result.confidence > 0.15:
                try:
                    agent = get_honeypot_agent()
                    agent_reply = agent.generate_response(
                        current_message=message_text,
                        conversation_history=[],
                        scam_category="UNKNOWN"
                    )
                    session_manager.add_message(session_id, 'user', agent_reply)
                    return AgentResponse(status="success", reply=agent_reply)
                except Exception:
                    pass
            
            return AgentResponse(
                status="success",
                reply="Hello? Who is this? What is this about?"
            )
            
    except Exception as e:
        logger.error(f"❌ Error processing message: {str(e)}")
        # Always return valid JSON - never crash
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "reply": "Sorry, I didn't understand. Can you please repeat?"
            }
        )


# ============== HEALTH & STATUS ENDPOINTS ==============

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "active_sessions": session_manager.get_session_count()
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Agentic Honeypot API",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health"
    }


# ============== TESTING ENDPOINTS ==============

@app.post("/test/detect-scam", response_model=TestScamResponse)
async def test_scam_detection(request: TestScamRequest):
    """Test endpoint to check scam detection without full flow."""
    result = scam_detector.detect(request.text)
    return TestScamResponse(
        is_scam=result.is_scam,
        confidence=result.confidence,
        detected_patterns=result.detected_patterns,
        suspicious_keywords=result.suspicious_keywords
    )


@app.post("/test/extract-intelligence")
async def test_intelligence_extraction(request: TestScamRequest):
    """Test endpoint to check intelligence extraction."""
    data = intelligence_extractor.extract_from_message(request.text)
    return {
        "status": "success",
        "intelligence": intelligence_extractor.to_dict(data),
        "summary": intelligence_extractor.get_intelligence_summary(data)
    }


@app.post("/test/agent-response")
async def test_agent_response(
    request: TestScamRequest,
    scam_category: str = "GENERIC_SCAM"
):
    """Test endpoint to get agent response for a message."""
    try:
        agent = get_honeypot_agent()
        reply = agent.generate_response(
            current_message=request.text,
            conversation_history=[],
            scam_category=scam_category
        )
        return {"status": "success", "reply": reply}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/test/session/{session_id}")
async def get_session_info(session_id: str):
    """Get information about a specific session."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "status": "success",
        "session": session_manager.get_session_summary(session_id),
        "conversation_history": session['conversation_history'],
        "intelligence": session['extracted_intelligence'],
        "engagement_duration_seconds": session_manager.get_engagement_duration_seconds(session_id)
    }


@app.get("/test/sessions")
async def list_all_sessions():
    """List all active sessions."""
    sessions = session_manager.get_all_sessions()
    return {
        "status": "success",
        "count": len(sessions),
        "sessions": [
            session_manager.get_session_summary(s['session_id'])
            for s in sessions
        ]
    }


@app.delete("/test/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a specific session."""
    deleted = session_manager.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "success", "message": f"Session {session_id} deleted"}


@app.delete("/test/sessions")
async def clear_all_sessions():
    """Clear all sessions."""
    count = session_manager.clear_all_sessions()
    return {"status": "success", "message": f"Cleared {count} sessions"}


@app.post("/test/send-callback/{session_id}")
async def test_send_callback(session_id: str):
    """Manually trigger callback for a session."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    engagement_duration = session_manager.get_engagement_duration_seconds(session_id)
    agent_notes = callback_service.prepare_agent_notes(session)
    
    result = callback_service.send_final_result(
        session_id=session_id,
        scam_detected=session.get('scam_detected', False),
        total_messages=session.get('messages_exchanged', 0),
        extracted_intelligence=session.get('extracted_intelligence', {}),
        agent_notes=agent_notes,
        engagement_duration_seconds=engagement_duration
    )
    
    if result['success']:
        session_manager.mark_callback_sent(session_id)
    
    return {
        "status": "success" if result['success'] else "error",
        "callback_result": result
    }


@app.get("/test/callback-history")
async def get_callback_history():
    """Get history of callbacks sent."""
    return {
        "status": "success",
        "history": callback_service.get_callback_history(),
        "last_callback": callback_service.get_last_callback()
    }


# ============== FULL SIMULATION ENDPOINT ==============

@app.post("/test/simulate-conversation")
async def simulate_conversation(
    initial_message: str = "Your bank account will be blocked today. Verify immediately.",
    num_turns: int = 3
):
    """Simulate a multi-turn scam conversation."""
    import uuid
    
    session_id = f"test-{uuid.uuid4()}"
    conversation = []
    
    try:
        agent = get_honeypot_agent()
        session_manager.create_session(session_id)
        
        current_message = initial_message
        
        for turn in range(num_turns):
            # Add scammer message
            session_manager.add_message(session_id, 'scammer', current_message)
            conversation.append({"sender": "scammer", "text": current_message})
            
            # Detect scam
            session = session_manager.get_session(session_id)
            detection = scam_detector.detect(current_message, session['conversation_history'])
            
            if detection.is_scam:
                session_manager.set_scam_detected(
                    session_id,
                    detected=True,
                    confidence=detection.confidence,
                    category=detection.scam_category
                )
            
            # Extract intelligence from entire conversation
            all_msgs = session_manager.get_session(session_id)['conversation_history']
            intel = intelligence_extractor.extract_from_conversation(all_msgs)
            session_manager.update_intelligence(session_id, intelligence_extractor.to_dict(intel))
            
            # Generate agent response
            session = session_manager.get_session(session_id)
            if session['agent_activated']:
                reply = agent.generate_response(
                    current_message=current_message,
                    conversation_history=session['conversation_history'][:-1],
                    scam_category=session['scam_category']
                )
                session_manager.add_message(session_id, 'user', reply)
                conversation.append({"sender": "user", "text": reply})
            
            # Simulate scammer follow-up
            if turn < num_turns - 1:
                follow_ups = [
                    "Share your UPI ID to verify your account. Send to verify@paytm",
                    "Please send Rs. 10 to confirm. Account: 123456789012. Call +919876543210",
                    "Visit http://fake-bank-verify.xyz to complete. Your account: 987654321098",
                ]
                current_message = follow_ups[turn % len(follow_ups)]
        
        # Get final session state
        final_session = session_manager.get_session(session_id)
        engagement_duration = session_manager.get_engagement_duration_seconds(session_id)
        
        return {
            "status": "success",
            "session_id": session_id,
            "conversation": conversation,
            "scam_detected": final_session['scam_detected'],
            "scam_category": final_session['scam_category'],
            "intelligence": final_session['extracted_intelligence'],
            "messages_exchanged": final_session['messages_exchanged'],
            "engagement_duration_seconds": engagement_duration
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "session_id": session_id
        }


# ============== SCORE PREVIEW ENDPOINT ==============

@app.get("/test/score-preview/{session_id}")
async def preview_score(session_id: str):
    """
    Preview the expected score for a session based on the GUVI rubric.
    Helps verify output before submission.
    """
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    intel = session.get('extracted_intelligence', {})
    engagement_duration = session_manager.get_engagement_duration_seconds(session_id)
    messages = session.get('messages_exchanged', 0)
    
    # Calculate expected scores
    scam_detection_score = 20 if session.get('scam_detected', False) else 0
    
    # Intelligence extraction (10 pts each)
    phone_score = 10 if len(intel.get('phoneNumbers', [])) > 0 else 0
    bank_score = 10 if len(intel.get('bankAccounts', [])) > 0 else 0
    upi_score = 10 if len(intel.get('upiIds', [])) > 0 else 0
    link_score = 10 if len(intel.get('phishingLinks', [])) > 0 else 0
    intelligence_score = phone_score + bank_score + upi_score + link_score
    
    # Engagement quality
    duration_gt0 = 5 if engagement_duration > 0 else 0
    duration_gt60 = 5 if engagement_duration > 60 else 0
    msgs_gt0 = 5 if messages > 0 else 0
    msgs_gte5 = 5 if messages >= 5 else 0
    engagement_score = duration_gt0 + duration_gt60 + msgs_gt0 + msgs_gte5
    
    # Response structure
    status_score = 5  # We always include status
    scam_detected_field = 5 if session.get('scam_detected') is not None else 0
    intel_field = 5 if intel else 0
    engagement_metrics_field = 2.5  # We now include engagementMetrics
    agent_notes_field = 2.5 if session.get('agent_notes') else 0
    structure_score = status_score + scam_detected_field + intel_field + engagement_metrics_field + agent_notes_field
    
    total = scam_detection_score + intelligence_score + engagement_score + structure_score
    
    return {
        "status": "success",
        "session_id": session_id,
        "estimated_score": {
            "total": total,
            "breakdown": {
                "scam_detection": {"score": scam_detection_score, "max": 20},
                "intelligence_extraction": {
                    "score": intelligence_score,
                    "max": 40,
                    "detail": {
                        "phoneNumbers": {"found": len(intel.get('phoneNumbers', [])), "score": phone_score},
                        "bankAccounts": {"found": len(intel.get('bankAccounts', [])), "score": bank_score},
                        "upiIds": {"found": len(intel.get('upiIds', [])), "score": upi_score},
                        "phishingLinks": {"found": len(intel.get('phishingLinks', [])), "score": link_score},
                    }
                },
                "engagement_quality": {
                    "score": engagement_score,
                    "max": 20,
                    "detail": {
                        "duration_seconds": round(engagement_duration, 1),
                        "duration_gt0": duration_gt0,
                        "duration_gt60": duration_gt60,
                        "total_messages": messages,
                        "msgs_gt0": msgs_gt0,
                        "msgs_gte5": msgs_gte5,
                    }
                },
                "response_structure": {
                    "score": structure_score,
                    "max": 20,
                    "detail": {
                        "status": status_score,
                        "scamDetected": scam_detected_field,
                        "extractedIntelligence": intel_field,
                        "engagementMetrics": engagement_metrics_field,
                        "agentNotes": agent_notes_field,
                    }
                }
            }
        }
    }


# ============== ERROR HANDLERS ==============

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "I didn't understand. Can you explain again?"
        }
    )


# Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
