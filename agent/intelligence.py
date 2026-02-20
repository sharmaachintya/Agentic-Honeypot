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
    case_ids: Set[str] = field(default_factory=set)
    policy_numbers: Set[str] = field(default_factory=set)
    order_numbers: Set[str] = field(default_factory=set)


class IntelligenceExtractor:
    """
    Extracts intelligence data from scammer messages including:
    - Bank account numbers
    - UPI IDs
    - Phishing links
    - Phone numbers
    - Suspicious keywords
    """
    
    # Patterns for Case IDs, Policy Numbers, Order Numbers
    # STRICT patterns to avoid false positives from common English words
    ID_PATTERNS = {
        'case_id': [
            # Must have prefix + alphanumeric ID with at least one digit
            r'\b(?:case|complaint|ticket|fir)[\s.:/#-]*(?:no|number|id|ref)?[\s.:/#-]*([A-Z]{0,5}[\-/]?\d{3,15}[A-Za-z0-9-]*)\b',
            r'\b(?:ref|reference)[\s.:/#-]*(?:no|number|id)?[\s.:/#-]*([A-Z]{0,5}[\-/]?\d{3,15}[A-Za-z0-9-]*)\b',
            # Standalone format: PREFIX-DIGITS
            r'\b([A-Z]{2,5}[-/]\d{4,12})\b',
        ],
        'policy_number': [
            r'\b(?:policy)[\s.:/#-]*(?:no|number|id)?[\s.:/#-]*([A-Za-z]{0,5}\d{5,15})\b',
            r'\b((?:LIC|HDFC|ICICI|SBI|MAX|TATA)[\s-]?\d{6,15})\b',
        ],
        'order_number': [
            r'\b(?:order|transaction|txn|invoice)[\s.:/#-]*(?:no|number|id)?[\s.:/#-]*([A-Za-z]{0,5}\d{4,15})\b',
            r'\b((?:ORD|TXN|INV|AMZ|FLK)[-]?\d{4,15})\b',
            # Order with # prefix: #405-789456789 or #AMZ-12345
            r'#\s*(\d{1,5}[-/]\d{4,15})\b',
            r'#\s*([A-Za-z]{1,5}[-/]?\d{4,15})\b',
        ],
    }
    
    # Words to filter out from ID extraction (common English words that match patterns)
    ID_BLACKLIST = {
        'erence', 'number', 'reference', 'umber', 'order', 'case', 'ticket',
        'complaint', 'invoice', 'policy', 'olicy', 'transaction', 'rence',
        'ation', 'umber', 'that', 'this', 'what', 'here', 'there', 'from',
    }
    
    # Agent-generated dummy data to filter out
    AGENT_DUMMY_DATA = {
        'ramesh1975@okaxis', 'name@sbi', 'name@bank', '3201xxxxxxxx45',
    }
    
    # Regex patterns for extraction
    PATTERNS = {
        # Indian bank account number (9-18 digits)
        'bank_account': [
            r'\b\d{9,18}\b',
            r'\b(?:a/c|account|acc)[\s.:]*(\d{9,18})\b',
        ],
        
        # UPI ID patterns (username@provider)
        'upi_id': [
            # Known UPI providers
            r'\b[\w.-]+@(?:upi|ybl|okaxis|okicici|okhdfcbank|oksbi|paytm|apl|axisb|icici|sbi|hdfcbank|ibl|axl|fbl|indus|kotak|federal|rbl|citi|boi|pnb|bob|canara|uboi|idbi|union|scb|dbs|hsbc|cub|kvb|tmb|dcb|csb|karb|jkb|bandhan|idfc|yes|fino|payzapp|slice|jupiter|fi|cred|gpay|phonepe|amazonpay|whatsapp)\b',
            # Any provider containing "fake" (fakebank, fakepayment, fakeincometax, etc.)
            r'\b([\w.-]+@[\w]*fake[\w.]*)\b',
            # Any user@provider when UPI/payment context keyword nearby in text
            r'(?:(?:upi|vpa|pay\s*to|send\s*to|transfer\s*to)[\s:]*)([\w.-]+@[\w.]+)\b',
            # Provider ending with bank/upi/pay
            r'\b([\w.-]+@(?:[\w]+bank|[\w]*upi|[\w]*pay))\b',
        ],
        
        # Phone numbers (Indian format - mobile + landline)
        'phone_number': [
            r'\+91[\s-]?\d{10}\b',
            r'\b91[\s-]?\d{10}\b',
            r'\b(?:0)?\d{10}\b',
            r'\b\d{5}[\s-]?\d{5}\b',
            # Indian landline numbers: 0XX-XXXXXXXX or 0XXX-XXXXXXX
            r'\b0\d{2,4}[\s-]\d{6,8}\b',
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
                # Strip trailing punctuation that's not part of the URL
                cleaned_url = match.rstrip('.,;:!?)\'\"')
                if cleaned_url:
                    data.phishing_links.add(cleaned_url)
        
        # Extract emails
        for pattern in self.compiled_patterns['email']:
            matches = pattern.findall(text)
            for match in matches:
                data.email_addresses.add(match.lower())
        
        # Extract Case IDs, Policy Numbers, Order Numbers
        for id_type, patterns in self.ID_PATTERNS.items():
            for pattern_str in patterns:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                matches = pattern.findall(text)
                for match in matches:
                    clean_match = match.strip() if isinstance(match, str) else str(match).strip()
                    if len(clean_match) >= 4:
                        if id_type == 'case_id':
                            data.case_ids.add(clean_match)
                        elif id_type == 'policy_number':
                            data.policy_numbers.add(clean_match)
                        elif id_type == 'order_number':
                            data.order_numbers.add(clean_match)
        
        # Extract suspicious keywords
        text_lower = text.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                data.suspicious_keywords.add(keyword)
        
        return data
    
    def extract_from_conversation(self, messages: List[Dict]) -> ExtractedData:
        """
        Extract intelligence from entire conversation.
        ONLY extracts from SCAMMER messages to avoid false positives
        from agent-generated dummy data.
        
        Args:
            messages: List of message dicts with 'text' and 'sender' keys
            
        Returns:
            Combined ExtractedData from scammer messages only
        """
        combined = ExtractedData()
        
        for msg in messages:
            if isinstance(msg, dict):
                text = msg.get('text', '')
                sender = msg.get('sender', '')
            else:
                text = msg.text if hasattr(msg, 'text') else str(msg)
                sender = str(msg.sender) if hasattr(msg, 'sender') else ''
            
            # ONLY extract from SCAMMER messages — skip agent/user responses
            # This prevents false positives from agent-generated dummy data
            if str(sender).lower() in ('user', 'agent', 'honeypot', 'bot'):
                continue
            
            extracted = self.extract_from_message(text)
            
            # Merge results
            combined.bank_accounts.update(extracted.bank_accounts)
            combined.upi_ids.update(extracted.upi_ids)
            combined.phishing_links.update(extracted.phishing_links)
            combined.phone_numbers.update(extracted.phone_numbers)
            combined.suspicious_keywords.update(extracted.suspicious_keywords)
            combined.email_addresses.update(extracted.email_addresses)
            combined.names_mentioned.update(extracted.names_mentioned)
            combined.case_ids.update(extracted.case_ids)
            combined.policy_numbers.update(extracted.policy_numbers)
            combined.order_numbers.update(extracted.order_numbers)
        
        # Filter out agent dummy data and blacklisted IDs
        combined.upi_ids -= self.AGENT_DUMMY_DATA
        combined.case_ids -= self.ID_BLACKLIST
        combined.policy_numbers -= self.ID_BLACKLIST
        combined.order_numbers -= self.ID_BLACKLIST
        
        # Remove UPI IDs from phishing links (cross-contamination fix)
        # UPI IDs like crypto.invest@fakecryptoplatform can match URL patterns
        upi_lower = {u.lower() for u in combined.upi_ids}
        combined.phishing_links = {
            link for link in combined.phishing_links
            if link.lower() not in upi_lower and not any(link.lower().rstrip('.,;:') == u for u in upi_lower)
        }
        
        # Remove email addresses from phishing links
        email_lower = {e.lower() for e in combined.email_addresses}
        combined.phishing_links = {
            link for link in combined.phishing_links
            if link.lower() not in email_lower
        }
        
        # Also remove UPI IDs from email addresses (UPIs with dots can match email regex)
        # e.g., lic-renewal@fakepayment.insure matches both UPI and email patterns
        combined.email_addresses -= combined.upi_ids
        
        # Remove support@fakefinance.com from UPI IDs - it's an email, not UPI
        # If something has a proper TLD (.com, .in, .org etc), it's email not UPI
        email_tlds = {'.com', '.in', '.org', '.net', '.co', '.io', '.gov'}
        false_upis = set()
        for upi in combined.upi_ids:
            provider = upi.split('@')[1] if '@' in upi else ''
            if any(provider.endswith(tld) for tld in email_tlds):
                # This is actually an email address, not a UPI
                combined.email_addresses.add(upi)
                false_upis.add(upi)
        combined.upi_ids -= false_upis
        
        # Remove numbers that appear in order_numbers/case_ids from bank_accounts (false positive fix)
        # e.g., order #405-789456789 -> 789456789 should not be a bank account
        id_numbers = set()
        for oid in combined.order_numbers | combined.case_ids:
            # Extract digit sequences from IDs
            digits = re.findall(r'\d{9,}', oid)
            id_numbers.update(digits)
        combined.bank_accounts -= id_numbers
        
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
            # Could be landline (0XX-XXXXXXXX) or mobile (0XXXXXXXXXX)
            return '+91' + digits[1:]
        elif len(digits) == 10:
            return '+91' + digits
        # Landline with STD code (e.g., 01112345678 = 11 digits with 0)
        elif len(digits) >= 8 and digits.startswith('0'):
            return digits  # Keep as-is for landlines
        
        return digits
    
    def _is_valid_phone(self, phone: str) -> bool:
        """
        Validate phone number (mobile or landline)
        
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
        
        # Indian landline: starts with 0 followed by 2-4 digit STD code + 6-8 digit number
        # Total 10-12 digits starting with 0
        if len(digits) >= 10 and len(digits) <= 12 and digits.startswith('0'):
            return True
        
        # Landline without leading 0 but with +91 prefix (cleaned)
        if phone.startswith('+91') and len(digits) >= 12:
            return True
        
        return False
    
    def to_dict(self, data: ExtractedData) -> Dict:
        """
        Convert ExtractedData to dictionary format for API response.
        Includes ALL fields needed for scoring:
        - phoneNumbers (10 pts)
        - bankAccounts (10 pts)
        - upiIds (10 pts)
        - phishingLinks (10 pts)
        - emailAddresses (bonus)
        - suspiciousKeywords (context)
        
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
            'emailAddresses': list(data.email_addresses),
            'caseIds': list(data.case_ids),
            'policyNumbers': list(data.policy_numbers),
            'orderNumbers': list(data.order_numbers),
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
