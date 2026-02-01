"""
Pydantic models for API request/response schemas
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class SenderType(str, Enum):
    SCAMMER = "scammer"
    USER = "user"


class ChannelType(str, Enum):
    SMS = "SMS"
    WHATSAPP = "WhatsApp"
    EMAIL = "Email"
    CHAT = "Chat"


# ============== REQUEST MODELS ==============

class Message(BaseModel):
    """Individual message in conversation"""
    sender: SenderType
    text: str
    timestamp: str  # ISO-8601 format


class Metadata(BaseModel):
    """Optional metadata about the message"""
    channel: Optional[ChannelType] = ChannelType.SMS
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class IncomingMessageRequest(BaseModel):
    """Main API request model for incoming messages"""
    sessionId: str = Field(..., description="Unique session identifier")
    message: Message = Field(..., description="The latest incoming message")
    conversationHistory: List[Message] = Field(
        default=[], 
        description="Previous messages in the conversation"
    )
    metadata: Optional[Metadata] = Field(
        default=None,
        description="Optional metadata about the channel"
    )


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
    """Intelligence extracted from scammer conversation"""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class FinalResultPayload(BaseModel):
    """Payload for GUVI final result callback"""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


# ============== SESSION MODELS ==============

class SessionData(BaseModel):
    """Session data stored in memory"""
    session_id: str
    scam_detected: bool = False
    scam_confidence: float = 0.0
    agent_activated: bool = False
    messages_exchanged: int = 0
    conversation_history: List[Message] = Field(default_factory=list)
    extracted_intelligence: ExtractedIntelligence = Field(
        default_factory=ExtractedIntelligence
    )
    agent_notes: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
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
