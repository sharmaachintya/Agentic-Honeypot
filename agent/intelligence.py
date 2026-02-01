"""
Intelligence Extraction Module
Extracts actionable intelligence from scammer conversations
"""
import re
from typing import List, Dict, Set
from dataclasses import dataclass, field


@dataclass
class ExtractedData:
    """Container for extracted intelligence data"""
    bank_accounts: Set[str] = field(default_factory=set)
    upi_ids: Set[str] = field(default_factory=set)
    phishing_links: Set[str] = field(default_factory=set)
    phone_numbers: Set[str] = field(default_factory=set)
    suspicious_keywords: Set[str] = field(default_factory=set)
    email_addresses: Set[str] = field(default_factory=set)
    names_mentioned: Set[str] = field(default_factory=set)


class IntelligenceExtractor:
    """
    Extracts intelligence data from scammer messages including:
    - Bank account numbers
    - UPI IDs
    - Phishing links
    - Phone numbers
    - Suspicious keywords
    """
    
    # Regex patterns for extraction
    PATTERNS = {
        # Indian bank account number (9-18 digits)
        'bank_account': [
            r'\b\d{9,18}\b',
            r'\b(?:a/c|account|acc)[\s.:]*(\d{9,18})\b',
        ],
        
        # UPI ID patterns (username@provider)
        'upi_id': [
            r'\b[\w.-]+@(?:upi|ybl|okaxis|okicici|okhdfcbank|oksbi|paytm|apl|axisb|icici|sbi|hdfcbank|ibl|axl|fbl|indus|kotak|federal|rbl|citi|boi|pnb|bob|canara|uboi|idbi|union|scb|dbs|hsbc|cub|kvb|tmb|dcb|csb|karb|jkb|bandhan|idfc|yes|fino|payzapp|slice|jupiter|fi|cred|gpay|phonepe|amazonpay|whatsapp)\b',
            r'\b[\w.-]+@[\w]+\b(?=.*(?:upi|payment|pay|transfer))',
        ],
        
        # Phone numbers (Indian format)
        'phone_number': [
            r'\+91[\s-]?\d{10}\b',
            r'\b91[\s-]?\d{10}\b',
            r'\b(?:0)?\d{10}\b',
            r'\b\d{5}[\s-]?\d{5}\b',
        ],
        
        # URLs and links
        'url': [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[^\s<>"{}|\\^`\[\]]+',
            r'\b[\w-]+\.(?:com|in|org|net|xyz|tk|ml|ga|cf|gq|top|work|click|info|co\.in|online|site|website|link|app)[^\s]*',
        ],
        
        # Email addresses
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        
        # IFSC Code
        'ifsc': [
            r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        ],
    }
    
    # Keywords that indicate scam behavior
    SUSPICIOUS_KEYWORDS = [
        # Urgency
        'urgent', 'immediately', 'now', 'today', 'asap', 'quick', 'fast',
        'expire', 'expiring', 'deadline', 'last chance', 'final warning',
        
        # Threats
        'blocked', 'suspended', 'deactivated', 'frozen', 'restricted',
        'legal action', 'police', 'arrest', 'penalty', 'fine',
        
        # Financial
        'upi', 'bank', 'account', 'transfer', 'payment', 'otp', 'pin',
        'cvv', 'card', 'kyc', 'verify', 'verification', 'update',
        
        # Rewards
        'prize', 'winner', 'lottery', 'cashback', 'refund', 'reward',
        'congratulations', 'selected', 'lucky',
        
        # Identity
        'aadhaar', 'aadhar', 'pan', 'passport', 'identity',
        
        # Action words
        'click', 'link', 'download', 'install', 'share', 'send',
    ]
    
    def __init__(self):
        """Initialize the intelligence extractor"""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency"""
        self.compiled_patterns = {}
        for key, patterns in self.PATTERNS.items():
            self.compiled_patterns[key] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def extract_from_message(self, text: str) -> ExtractedData:
        """
        Extract intelligence from a single message
        
        Args:
            text: Message text to analyze
            
        Returns:
            ExtractedData with all found intelligence
        """
        data = ExtractedData()
        
        # Extract bank accounts
        for pattern in self.compiled_patterns['bank_account']:
            matches = pattern.findall(text)
            for match in matches:
                # Filter out phone numbers (10 digits starting with 6-9)
                if len(match) == 10 and match[0] in '6789':
                    continue
                # Filter out common non-account numbers
                if self._is_valid_bank_account(match):
                    data.bank_accounts.add(match)
        
        # Extract UPI IDs
        for pattern in self.compiled_patterns['upi_id']:
            matches = pattern.findall(text)
            for match in matches:
                if self._is_valid_upi(match):
                    data.upi_ids.add(match.lower())
        
        # Extract phone numbers
        for pattern in self.compiled_patterns['phone_number']:
            matches = pattern.findall(text)
            for match in matches:
                cleaned = self._clean_phone_number(match)
                if cleaned and self._is_valid_phone(cleaned):
                    data.phone_numbers.add(cleaned)
        
        # Extract URLs
        for pattern in self.compiled_patterns['url']:
            matches = pattern.findall(text)
            for match in matches:
                data.phishing_links.add(match)
        
        # Extract emails
        for pattern in self.compiled_patterns['email']:
            matches = pattern.findall(text)
            for match in matches:
                data.email_addresses.add(match.lower())
        
        # Extract suspicious keywords
        text_lower = text.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                data.suspicious_keywords.add(keyword)
        
        return data
    
    def extract_from_conversation(self, messages: List[Dict]) -> ExtractedData:
        """
        Extract intelligence from entire conversation
        
        Args:
            messages: List of message dicts with 'text' and 'sender' keys
            
        Returns:
            Combined ExtractedData from all messages
        """
        combined = ExtractedData()
        
        for msg in messages:
            # Get text from message (handle both dict and object)
            if isinstance(msg, dict):
                text = msg.get('text', '')
                sender = msg.get('sender', '')
            else:
                text = msg.text if hasattr(msg, 'text') else str(msg)
                sender = str(msg.sender) if hasattr(msg, 'sender') else ''
            
            # Only extract from scammer messages (more valuable intelligence)
            # But also check user messages for any leaked info
            extracted = self.extract_from_message(text)
            
            # Merge results
            combined.bank_accounts.update(extracted.bank_accounts)
            combined.upi_ids.update(extracted.upi_ids)
            combined.phishing_links.update(extracted.phishing_links)
            combined.phone_numbers.update(extracted.phone_numbers)
            combined.suspicious_keywords.update(extracted.suspicious_keywords)
            combined.email_addresses.update(extracted.email_addresses)
            combined.names_mentioned.update(extracted.names_mentioned)
        
        return combined
    
    def _is_valid_bank_account(self, account: str) -> bool:
        """
        Validate if string looks like a bank account number
        
        Args:
            account: Potential account number
            
        Returns:
            True if valid
        """
        # Must be 9-18 digits
        if not account.isdigit():
            return False
        
        length = len(account)
        if length < 9 or length > 18:
            return False
        
        # Filter out sequential numbers
        if account == account[0] * length:
            return False
        
        # Filter out 10-digit phone numbers
        if length == 10 and account[0] in '6789':
            return False
        
        return True
    
    def _is_valid_upi(self, upi_id: str) -> bool:
        """
        Validate UPI ID format
        
        Args:
            upi_id: Potential UPI ID
            
        Returns:
            True if valid format
        """
        if '@' not in upi_id:
            return False
        
        parts = upi_id.split('@')
        if len(parts) != 2:
            return False
        
        username, provider = parts
        
        # Username must be at least 3 chars
        if len(username) < 3:
            return False
        
        # Provider must not be empty
        if len(provider) < 2:
            return False
        
        return True
    
    def _clean_phone_number(self, phone: str) -> str:
        """
        Clean and normalize phone number
        
        Args:
            phone: Raw phone number string
            
        Returns:
            Cleaned phone number
        """
        # Remove all non-digit characters
        digits = re.sub(r'\D', '', phone)
        
        # Handle Indian numbers
        if len(digits) == 12 and digits.startswith('91'):
            return '+91' + digits[2:]
        elif len(digits) == 11 and digits.startswith('0'):
            return '+91' + digits[1:]
        elif len(digits) == 10:
            return '+91' + digits
        
        return digits
    
    def _is_valid_phone(self, phone: str) -> bool:
        """
        Validate phone number
        
        Args:
            phone: Cleaned phone number
            
        Returns:
            True if valid
        """
        digits = re.sub(r'\D', '', phone)
        
        # Indian mobile numbers start with 6-9
        if len(digits) >= 10:
            last_10 = digits[-10:]
            if last_10[0] in '6789':
                return True
        
        return False
    
    def to_dict(self, data: ExtractedData) -> Dict:
        """
        Convert ExtractedData to dictionary format for API response
        
        Args:
            data: ExtractedData object
            
        Returns:
            Dictionary with lists instead of sets
        """
        return {
            'bankAccounts': list(data.bank_accounts),
            'upiIds': list(data.upi_ids),
            'phishingLinks': list(data.phishing_links),
            'phoneNumbers': list(data.phone_numbers),
            'suspiciousKeywords': list(data.suspicious_keywords),
        }
    
    def get_intelligence_summary(self, data: ExtractedData) -> str:
        """
        Generate a summary of extracted intelligence
        
        Args:
            data: ExtractedData object
            
        Returns:
            Summary string
        """
        parts = []
        
        if data.bank_accounts:
            parts.append(f"Bank accounts: {', '.join(data.bank_accounts)}")
        if data.upi_ids:
            parts.append(f"UPI IDs: {', '.join(data.upi_ids)}")
        if data.phone_numbers:
            parts.append(f"Phone numbers: {', '.join(data.phone_numbers)}")
        if data.phishing_links:
            parts.append(f"Links: {', '.join(data.phishing_links)}")
        if data.suspicious_keywords:
            parts.append(f"Keywords: {', '.join(list(data.suspicious_keywords)[:10])}")
        
        if not parts:
            return "No significant intelligence extracted yet."
        
        return "; ".join(parts)
    
    def has_sufficient_intelligence(self, data: ExtractedData) -> bool:
        """
        Check if enough intelligence has been extracted
        
        Args:
            data: ExtractedData object
            
        Returns:
            True if sufficient intelligence gathered
        """
        # Consider sufficient if we have at least one high-value item
        high_value = (
            len(data.bank_accounts) > 0 or
            len(data.upi_ids) > 0 or
            len(data.phishing_links) > 0 or
            len(data.phone_numbers) > 0
        )
        
        # Or if we have multiple keywords indicating clear scam
        keyword_rich = len(data.suspicious_keywords) >= 5
        
        return high_value or keyword_rich
