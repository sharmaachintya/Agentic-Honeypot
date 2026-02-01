"""
Scam Detection Module
Detects scam intent from incoming messages using pattern matching and heuristics
"""
import re
from typing import Tuple, List, Dict
from dataclasses import dataclass


@dataclass
class ScamDetectionResult:
    """Result of scam detection analysis"""
    is_scam: bool
    confidence: float
    detected_patterns: List[str]
    suspicious_keywords: List[str]
    scam_category: str


class ScamDetector:
    """
    Detects scam messages using pattern matching and keyword analysis.
    Focuses on common Indian scam patterns: UPI fraud, bank fraud, phishing, etc.
    """
    
    # Urgency patterns that scammers commonly use
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|today|now|asap|quick|fast)\b',
        r'\b(within \d+ (hour|minute|day)s?)\b',
        r'\b(last chance|final warning|act now|don\'?t delay)\b',
        r'\b(expire|expiring|expired|deadline)\b',
        r'\b(limited time|time sensitive|running out)\b',
    ]
    
    # Threat patterns
    THREAT_PATTERNS = [
        r'\b(block|blocked|suspend|suspended|deactivate|deactivated)\b',
        r'\b(freeze|frozen|restrict|restricted|terminate|terminated)\b',
        r'\b(legal action|police|arrest|court|lawsuit|penalty)\b',
        r'\b(fine|penalty|charge|fee)\b',
        r'\b(lose|lost|losing) (access|money|account)\b',
    ]
    
    # Financial request patterns
    FINANCIAL_PATTERNS = [
        r'\b(upi|upi id|upi pin|vpa)\b',
        r'\b(bank account|account number|ifsc|swift)\b',
        r'\b(otp|one time password|verification code|pin)\b',
        r'\b(cvv|card number|expiry date|credit card|debit card)\b',
        r'\b(transfer|send money|pay|payment)\b',
        r'\b(kyc|verification|verify|update)\b',
        r'\b(refund|cashback|reward|prize|lottery|winner)\b',
        r'\b(aadhaar|aadhar|pan card|pan number)\b',
    ]
    
    # Impersonation patterns (pretending to be authority)
    IMPERSONATION_PATTERNS = [
        r'\b(bank|sbi|hdfc|icici|axis|rbi|reserve bank)\b',
        r'\b(customer care|support|helpline|service)\b',
        r'\b(government|ministry|department|official)\b',
        r'\b(amazon|flipkart|paytm|phonepe|gpay|google pay)\b',
        r'\b(income tax|it department|gst|customs)\b',
        r'\b(telecom|jio|airtel|vodafone|bsnl|trai)\b',
    ]
    
    # Phishing link patterns
    PHISHING_PATTERNS = [
        r'https?://[^\s]+',  # Any URL
        r'\b(click|tap|visit|go to|open)\s+(this|the)?\s*(link|url|website)\b',
        r'bit\.ly|tinyurl|shorturl|goo\.gl',
        r'\.(xyz|tk|ml|ga|cf|gq|top|work|click)\b',  # Suspicious TLDs
    ]
    
    # Common scam phrases
    SCAM_PHRASES = [
        'your account will be blocked',
        'verify your account',
        'update your kyc',
        'share your otp',
        'send money to',
        'you have won',
        'claim your prize',
        'refund pending',
        'cashback offer',
        'link your aadhaar',
        'pan verification',
        'sim will be blocked',
        'dear customer',
        'account suspended',
        'unauthorized transaction',
        'security alert',
        'confirm your identity',
    ]
    
    # Suspicious keywords to extract
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'immediately', 'blocked', 'suspended', 'verify',
        'otp', 'pin', 'upi', 'bank', 'account', 'transfer', 'payment',
        'kyc', 'aadhaar', 'pan', 'refund', 'cashback', 'prize', 'winner',
        'click', 'link', 'update', 'confirm', 'security', 'alert',
        'warning', 'expire', 'deadline', 'penalty', 'legal'
    ]

    def __init__(self):
        """Initialize the scam detector with compiled patterns"""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency"""
        self.compiled_urgency = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS]
        self.compiled_threat = [re.compile(p, re.IGNORECASE) for p in self.THREAT_PATTERNS]
        self.compiled_financial = [re.compile(p, re.IGNORECASE) for p in self.FINANCIAL_PATTERNS]
        self.compiled_impersonation = [re.compile(p, re.IGNORECASE) for p in self.IMPERSONATION_PATTERNS]
        self.compiled_phishing = [re.compile(p, re.IGNORECASE) for p in self.PHISHING_PATTERNS]
    
    def detect(self, text: str, conversation_history: List[Dict] = None) -> ScamDetectionResult:
        """
        Analyze text for scam intent
        
        Args:
            text: The message text to analyze
            conversation_history: Previous messages for context
            
        Returns:
            ScamDetectionResult with detection details
        """
        text_lower = text.lower()
        detected_patterns = []
        confidence = 0.0
        
        # Check urgency patterns (weight: 0.15)
        urgency_matches = self._check_patterns(text, self.compiled_urgency)
        if urgency_matches:
            detected_patterns.extend([f"urgency:{m}" for m in urgency_matches])
            confidence += min(0.15, 0.05 * len(urgency_matches))
        
        # Check threat patterns (weight: 0.20)
        threat_matches = self._check_patterns(text, self.compiled_threat)
        if threat_matches:
            detected_patterns.extend([f"threat:{m}" for m in threat_matches])
            confidence += min(0.20, 0.07 * len(threat_matches))
        
        # Check financial patterns (weight: 0.25)
        financial_matches = self._check_patterns(text, self.compiled_financial)
        if financial_matches:
            detected_patterns.extend([f"financial:{m}" for m in financial_matches])
            confidence += min(0.25, 0.08 * len(financial_matches))
        
        # Check impersonation patterns (weight: 0.15)
        impersonation_matches = self._check_patterns(text, self.compiled_impersonation)
        if impersonation_matches:
            detected_patterns.extend([f"impersonation:{m}" for m in impersonation_matches])
            confidence += min(0.15, 0.05 * len(impersonation_matches))
        
        # Check phishing patterns (weight: 0.15)
        phishing_matches = self._check_patterns(text, self.compiled_phishing)
        if phishing_matches:
            detected_patterns.extend([f"phishing:{m}" for m in phishing_matches])
            confidence += min(0.15, 0.10 * len(phishing_matches))
        
        # Check common scam phrases (weight: 0.10)
        phrase_matches = self._check_phrases(text_lower)
        if phrase_matches:
            detected_patterns.extend([f"phrase:{m}" for m in phrase_matches])
            confidence += min(0.10, 0.05 * len(phrase_matches))
        
        # Extract suspicious keywords found
        suspicious_keywords = self._extract_suspicious_keywords(text_lower)
        
        # Determine scam category
        scam_category = self._determine_category(detected_patterns)
        
        # Consider conversation history for context boost
        if conversation_history:
            history_boost = self._analyze_history(conversation_history)
            confidence = min(1.0, confidence + history_boost)
        
        # Normalize confidence
        confidence = min(1.0, confidence)
        
        # Determine if scam (threshold: 0.30)
        is_scam = confidence >= 0.30
        
        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(confidence, 2),
            detected_patterns=detected_patterns,
            suspicious_keywords=suspicious_keywords,
            scam_category=scam_category
        )
    
    def _check_patterns(self, text: str, compiled_patterns: List) -> List[str]:
        """Check text against compiled regex patterns"""
        matches = []
        for pattern in compiled_patterns:
            found = pattern.findall(text)
            if found:
                # Handle tuple results from groups
                for f in found:
                    if isinstance(f, tuple):
                        matches.append(f[0])
                    else:
                        matches.append(f)
        return list(set(matches))
    
    def _check_phrases(self, text_lower: str) -> List[str]:
        """Check for common scam phrases"""
        matches = []
        for phrase in self.SCAM_PHRASES:
            if phrase in text_lower:
                matches.append(phrase)
        return matches
    
    def _extract_suspicious_keywords(self, text_lower: str) -> List[str]:
        """Extract suspicious keywords from text"""
        found = []
        words = re.findall(r'\b\w+\b', text_lower)
        for word in words:
            if word in self.SUSPICIOUS_KEYWORDS:
                found.append(word)
        return list(set(found))
    
    def _determine_category(self, detected_patterns: List[str]) -> str:
        """Determine the category of scam based on detected patterns"""
        pattern_str = ' '.join(detected_patterns).lower()
        
        if 'upi' in pattern_str or 'payment' in pattern_str:
            return "UPI_FRAUD"
        elif 'bank' in pattern_str or 'account' in pattern_str:
            return "BANK_FRAUD"
        elif 'phishing' in pattern_str or 'link' in pattern_str or 'url' in pattern_str:
            return "PHISHING"
        elif 'kyc' in pattern_str or 'verify' in pattern_str:
            return "KYC_FRAUD"
        elif 'prize' in pattern_str or 'winner' in pattern_str or 'lottery' in pattern_str:
            return "LOTTERY_SCAM"
        elif 'refund' in pattern_str or 'cashback' in pattern_str:
            return "REFUND_SCAM"
        elif 'sim' in pattern_str or 'telecom' in pattern_str:
            return "SIM_FRAUD"
        elif len(detected_patterns) > 0:
            return "GENERIC_SCAM"
        else:
            return "UNKNOWN"
    
    def _analyze_history(self, conversation_history: List[Dict]) -> float:
        """Analyze conversation history for additional scam signals"""
        boost = 0.0
        
        for msg in conversation_history:
            text = msg.get('text', '') if isinstance(msg, dict) else msg.text
            sender = msg.get('sender', '') if isinstance(msg, dict) else msg.sender
            
            # Only analyze scammer messages
            if str(sender).lower() == 'scammer':
                # Check if previous messages also had scam patterns
                result = self.detect(text)
                if result.is_scam:
                    boost += 0.05
        
        return min(0.15, boost)  # Max boost from history
    
    def get_detection_summary(self, result: ScamDetectionResult) -> str:
        """Generate a human-readable summary of detection"""
        if not result.is_scam:
            return "No significant scam indicators detected."
        
        summary_parts = [
            f"Scam detected with {result.confidence*100:.0f}% confidence.",
            f"Category: {result.scam_category}.",
        ]
        
        if result.detected_patterns:
            summary_parts.append(f"Patterns found: {', '.join(result.detected_patterns[:5])}.")
        
        if result.suspicious_keywords:
            summary_parts.append(f"Suspicious keywords: {', '.join(result.suspicious_keywords[:5])}.")
        
        return " ".join(summary_parts)
