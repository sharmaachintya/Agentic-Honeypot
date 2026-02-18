"""
Pydantic models for API request/response schemas
Flexible version - accepts various input formats

Updated for scoring rubric compliance:
- Includes emailAddresses in ExtractedIntelligence
- Includes engagementMetrics in FinalResultPayload
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime


# ============== REQUEST MODELS (FLEXIBLE) ==============

class Message(BaseModel):
    """Individual message in conversation - flexible validation"""
    sender: str
    text: str
    timestamp: Optional[str] = None

    class Config:
        extra = "ignore"


class Metadata(BaseModel):
    """Optional metadata about the message - flexible"""
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

    class Config:
        extra = "ignore"


class IncomingMessageRequest(BaseModel):
    """Main API request model for incoming messages - flexible"""
    sessionId: str = Field(..., description="Unique session identifier")
    message: Message = Field(..., description="The latest incoming message")
    conversationHistory: Optional[List[Message]] = Field(
        default=[], 
        description="Previous messages in the conversation"
    )
    metadata: Optional[Metadata] = Field(
        default=None,
        description="Optional metadata about the channel"
    )

    class Config:
        extra = "ignore"


# ============== RESPONSE MODELS ==============

class AgentResponse(BaseModel):
    """Response from the honeypot agent"""
    status: str = Field(default="success", description="Status of the response")
    reply: str = Field(..., description="Agent's reply message")


class ErrorResponse(BaseModel):
    """Error response model"""
    status: str = "error"
    message: str
    detail: Optional[str] = None


# ============== INTELLIGENCE MODELS ==============

class ExtractedIntelligence(BaseModel):
    """
    Intelligence extracted from scammer conversation.
    
    Scoring (40 pts total):
    - phoneNumbers: 10 pts
    - bankAccounts: 10 pts
    - upiIds: 10 pts
    - phishingLinks: 10 pts
    - emailAddresses: bonus/context
    - suspiciousKeywords: context
    """
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    """
    Engagement metrics for scoring.
    
    Scoring (20 pts total):
    - engagementDurationSeconds > 0: 5 pts
    - engagementDurationSeconds > 60: 5 pts
    - totalMessages > 0: 5 pts
    - totalMessages >= 5: 5 pts
    """
    engagementDurationSeconds: float = Field(default=0.0)
    totalMessages: int = Field(default=0)


class FinalResultPayload(BaseModel):
    """
    Payload for GUVI final result callback.
    
    Response Structure Scoring (20 pts):
    - status: 5 pts
    - scamDetected: 5 pts
    - extractedIntelligence: 5 pts
    - engagementMetrics: 2.5 pts
    - agentNotes: 2.5 pts
    """
    status: str = "success"
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    engagementMetrics: EngagementMetrics
    agentNotes: str


# ============== SESSION MODELS ==============

class SessionData(BaseModel):
    """Session data stored in memory"""
    session_id: str
    scam_detected: bool = False
    scam_confidence: float = 0.0
    agent_activated: bool = False
    messages_exchanged: int = 0
    conversation_history: List[dict] = Field(default_factory=list)
    extracted_intelligence: ExtractedIntelligence = Field(
        default_factory=ExtractedIntelligence
    )
    agent_notes: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    first_message_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_message_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    callback_sent: bool = False


# ============== TESTING MODELS ==============

class TestScamRequest(BaseModel):
    """Request model for testing scam detection"""
    text: str = Field(..., description="Text to analyze for scam intent")


class TestScamResponse(BaseModel):
    """Response model for scam detection test"""
    is_scam: bool
    confidence: float
    detected_patterns: List[str]
    suspicious_keywords: List[str]


class SessionInfoResponse(BaseModel):
    """Response model for session info endpoint"""
    session_id: str
    scam_detected: bool
    agent_activated: bool
    messages_exchanged: int
    intelligence: ExtractedIntelligence
    agent_notes: List[str]
    callback_sent: bool
    engagement_duration_seconds: float = 0.0
