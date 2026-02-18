"""
Scam Detection Module
Detects scam intent from incoming messages using pattern matching and heuristics.

Covers ALL 15 evaluation scenarios:
1. Bank Fraud          9. Crypto Investment
2. UPI Fraud          10. Customs Parcel
3. Phishing Link      11. Tech Support
4. KYC Fraud          12. Loan Approval
5. Job Scam           13. Income Tax
6. Lottery Scam       14. Refund Scam
7. Electricity Bill   15. Insurance
8. Govt Scheme
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
    Covers all 15 evaluation scenarios including Indian scam patterns.
    """
    
    # Urgency patterns that scammers commonly use
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|today|now|asap|quick|fast)\b',
        r'\b(within \d+ (hour|minute|day)s?)\b',
        r'\b(last chance|final warning|act now|don\'?t delay)\b',
        r'\b(expire|expiring|expired|deadline)\b',
        r'\b(limited time|time sensitive|running out)\b',
        r'\b(hurry|rush|before it\'?s too late)\b',
    ]
    
    # Threat patterns
    THREAT_PATTERNS = [
        r'\b(block|blocked|suspend|suspended|deactivate|deactivated)\b',
        r'\b(freeze|frozen|restrict|restricted|terminate|terminated)\b',
        r'\b(legal action|police|arrest|court|lawsuit|penalty)\b',
        r'\b(fine|penalty|charge|fee|prosecution)\b',
        r'\b(lose|lost|losing) (access|money|account)\b',
        r'\b(disconnect|disconnected|shut down|shut off)\b',
        r'\b(warrant|summon|notice|complaint)\b',
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
        r'\b(processing fee|registration fee|advance fee)\b',
        r'\b(premium|installment|emi|down payment)\b',
    ]
    
    # Impersonation patterns (pretending to be authority)
    IMPERSONATION_PATTERNS = [
        r'\b(bank|sbi|hdfc|icici|axis|rbi|reserve bank)\b',
        r'\b(customer care|support|helpline|service)\b',
        r'\b(government|ministry|department|official)\b',
        r'\b(amazon|flipkart|paytm|phonepe|gpay|google pay)\b',
        r'\b(income tax|it department|gst|customs)\b',
        r'\b(telecom|jio|airtel|vodafone|bsnl|trai)\b',
        r'\b(electricity|power|discom|electricity board)\b',
        r'\b(insurance|lic|policy|claim)\b',
        r'\b(microsoft|apple|google|windows|tech support)\b',
    ]
    
    # Phishing link patterns
    PHISHING_PATTERNS = [
        r'https?://[^\s]+',
        r'\b(click|tap|visit|go to|open)\s+(this|the)?\s*(link|url|website)\b',
        r'bit\.ly|tinyurl|shorturl|goo\.gl',
        r'\.(xyz|tk|ml|ga|cf|gq|top|work|click)\b',
    ]
    
    # Job scam patterns
    JOB_PATTERNS = [
        r'\b(job offer|work from home|earn from home|part time|full time)\b',
        r'\b(hiring|vacancy|recruitment|selected for job)\b',
        r'\b(salary|income|earn|earning)\s*(rs\.?|inr|₹)?\s*\d+',
        r'\b(data entry|typing job|online job|freelance)\b',
        r'\b(company|mnc|corporate|interview)\b',
        r'\b(joining fee|training fee|registration charge)\b',
    ]
    
    # Investment/Crypto scam patterns
    INVESTMENT_PATTERNS = [
        r'\b(invest|investment|trading|trade|forex)\b',
        r'\b(crypto|bitcoin|btc|ethereum|eth|coin)\b',
        r'\b(guaranteed return|high return|double your money)\b',
        r'\b(profit|roi|return on investment)\b',
        r'\b(mining|stake|staking|defi|nft)\b',
        r'\b(portfolio|mutual fund|stock|share market)\b',
    ]
    
    # Loan scam patterns
    LOAN_PATTERNS = [
        r'\b(loan|pre.?approved|instant loan|personal loan)\b',
        r'\b(credit score|cibil|emi|interest rate)\b',
        r'\b(sanction|disburse|disbursement)\b',
        r'\b(low interest|zero interest|no collateral)\b',
        r'\b(loan amount|loan offer|loan approved)\b',
    ]
    
    # Customs/Parcel scam patterns
    CUSTOMS_PATTERNS = [
        r'\b(customs|parcel|package|courier|delivery)\b',
        r'\b(seized|held|stuck|detained|impound)\b',
        r'\b(customs duty|clearance fee|release)\b',
        r'\b(shipment|consignment|cargo)\b',
        r'\b(from abroad|international|foreign)\b',
    ]
    
    # Tech support scam patterns
    TECH_SUPPORT_PATTERNS = [
        r'\b(virus|malware|infected|hacked|compromised)\b',
        r'\b(tech support|technical support|it support)\b',
        r'\b(remote access|teamviewer|anydesk)\b',
        r'\b(computer|laptop|device|system)\s*(is|has been)?\s*(slow|infected|hacked)',
        r'\b(license|subscription|expired|renew)\b',
        r'\b(microsoft|windows|apple|antivirus)\b',
    ]
    
    # Income tax scam patterns
    INCOME_TAX_PATTERNS = [
        r'\b(income tax|it department|it return|itr)\b',
        r'\b(tax refund|tax pending|tax due|tax notice)\b',
        r'\b(form 16|form 26|assessment|scrutiny)\b',
        r'\b(tds|tax deducted|tax credit)\b',
        r'\b(e.?filing|tax portal|traces)\b',
    ]
    
    # Electricity bill scam patterns
    ELECTRICITY_PATTERNS = [
        r'\b(electricity|power|electric|light)\s*(bill|connection|supply)\b',
        r'\b(meter|reading|unit|consumption)\b',
        r'\b(disconnect|disconnection|cut off|power cut)\b',
        r'\b(outstanding|overdue|pending)\s*(bill|amount|dues)\b',
        r'\b(electricity board|discom|power company)\b',
    ]
    
    # Government scheme scam patterns
    GOVT_SCHEME_PATTERNS = [
        r'\b(government|govt|sarkari|pm|pradhan mantri)\b',
        r'\b(scheme|yojana|subsidy|benefit|grant)\b',
        r'\b(ration|bpl|apl|pension|scholarship)\b',
        r'\b(aadhar|aadhaar|voter id|ration card)\b',
        r'\b(registration|apply|enroll|eligible)\b',
    ]
    
    # Insurance scam patterns
    INSURANCE_PATTERNS = [
        r'\b(insurance|policy|premium|cover|coverage)\b',
        r'\b(lic|health insurance|life insurance|motor insurance)\b',
        r'\b(claim|maturity|bonus|surrender)\b',
        r'\b(nominee|beneficiary|insured|policyholder)\b',
        r'\b(lapsed|renewal|reinstate)\b',
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
        'electricity will be disconnected',
        'power will be cut',
        'tax refund available',
        'loan pre-approved',
        'loan has been approved',
        'parcel is being held',
        'customs clearance required',
        'your computer has been infected',
        'virus detected',
        'your policy has matured',
        'insurance claim pending',
        'government scheme benefit',
        'work from home opportunity',
        'guaranteed returns',
        'double your investment',
        'selected for job',
    ]
    
    # Suspicious keywords to extract (expanded)
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'immediately', 'blocked', 'suspended', 'verify',
        'otp', 'pin', 'upi', 'bank', 'account', 'transfer', 'payment',
        'kyc', 'aadhaar', 'pan', 'refund', 'cashback', 'prize', 'winner',
        'click', 'link', 'update', 'confirm', 'security', 'alert',
        'warning', 'expire', 'deadline', 'penalty', 'legal',
        'loan', 'approved', 'pre-approved', 'interest', 'emi',
        'tax', 'income', 'it department', 'refund',
        'crypto', 'bitcoin', 'investment', 'guaranteed', 'returns',
        'customs', 'parcel', 'package', 'seized', 'clearance',
        'virus', 'infected', 'hacked', 'malware', 'tech support',
        'electricity', 'disconnection', 'power', 'bill',
        'insurance', 'policy', 'claim', 'premium', 'maturity',
        'government', 'scheme', 'subsidy', 'benefit', 'yojana',
        'job', 'hiring', 'work from home', 'salary', 'vacancy',
        'fee', 'processing', 'registration', 'advance',
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
        self.compiled_job = [re.compile(p, re.IGNORECASE) for p in self.JOB_PATTERNS]
        self.compiled_investment = [re.compile(p, re.IGNORECASE) for p in self.INVESTMENT_PATTERNS]
        self.compiled_loan = [re.compile(p, re.IGNORECASE) for p in self.LOAN_PATTERNS]
        self.compiled_customs = [re.compile(p, re.IGNORECASE) for p in self.CUSTOMS_PATTERNS]
        self.compiled_tech_support = [re.compile(p, re.IGNORECASE) for p in self.TECH_SUPPORT_PATTERNS]
        self.compiled_income_tax = [re.compile(p, re.IGNORECASE) for p in self.INCOME_TAX_PATTERNS]
        self.compiled_electricity = [re.compile(p, re.IGNORECASE) for p in self.ELECTRICITY_PATTERNS]
        self.compiled_govt_scheme = [re.compile(p, re.IGNORECASE) for p in self.GOVT_SCHEME_PATTERNS]
        self.compiled_insurance = [re.compile(p, re.IGNORECASE) for p in self.INSURANCE_PATTERNS]
    
    def detect(self, text: str, conversation_history: List[Dict] = None) -> ScamDetectionResult:
        """
        Analyze text for scam intent.
        
        Args:
            text: The message text to analyze
            conversation_history: Previous messages for context
            
        Returns:
            ScamDetectionResult with detection details
        """
        text_lower = text.lower()
        detected_patterns = []
        confidence = 0.0
        category_scores = {}
        
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
        
        # Check job scam patterns (weight: 0.15)
        job_matches = self._check_patterns(text, self.compiled_job)
        if job_matches:
            detected_patterns.extend([f"job_scam:{m}" for m in job_matches])
            confidence += min(0.15, 0.06 * len(job_matches))
            category_scores['JOB_SCAM'] = len(job_matches)
        
        # Check investment/crypto patterns (weight: 0.15)
        investment_matches = self._check_patterns(text, self.compiled_investment)
        if investment_matches:
            detected_patterns.extend([f"investment:{m}" for m in investment_matches])
            confidence += min(0.15, 0.06 * len(investment_matches))
            category_scores['CRYPTO_INVESTMENT'] = len(investment_matches)
        
        # Check loan patterns (weight: 0.15)
        loan_matches = self._check_patterns(text, self.compiled_loan)
        if loan_matches:
            detected_patterns.extend([f"loan:{m}" for m in loan_matches])
            confidence += min(0.15, 0.06 * len(loan_matches))
            category_scores['LOAN_SCAM'] = len(loan_matches)
        
        # Check customs/parcel patterns (weight: 0.15)
        customs_matches = self._check_patterns(text, self.compiled_customs)
        if customs_matches:
            detected_patterns.extend([f"customs:{m}" for m in customs_matches])
            confidence += min(0.15, 0.06 * len(customs_matches))
            category_scores['CUSTOMS_PARCEL'] = len(customs_matches)
        
        # Check tech support patterns (weight: 0.15)
        tech_matches = self._check_patterns(text, self.compiled_tech_support)
        if tech_matches:
            detected_patterns.extend([f"tech_support:{m}" for m in tech_matches])
            confidence += min(0.15, 0.06 * len(tech_matches))
            category_scores['TECH_SUPPORT'] = len(tech_matches)
        
        # Check income tax patterns (weight: 0.15)
        tax_matches = self._check_patterns(text, self.compiled_income_tax)
        if tax_matches:
            detected_patterns.extend([f"income_tax:{m}" for m in tax_matches])
            confidence += min(0.15, 0.06 * len(tax_matches))
            category_scores['INCOME_TAX'] = len(tax_matches)
        
        # Check electricity patterns (weight: 0.15)
        electricity_matches = self._check_patterns(text, self.compiled_electricity)
        if electricity_matches:
            detected_patterns.extend([f"electricity:{m}" for m in electricity_matches])
            confidence += min(0.15, 0.06 * len(electricity_matches))
            category_scores['ELECTRICITY_BILL'] = len(electricity_matches)
        
        # Check government scheme patterns (weight: 0.15)
        govt_matches = self._check_patterns(text, self.compiled_govt_scheme)
        if govt_matches:
            detected_patterns.extend([f"govt_scheme:{m}" for m in govt_matches])
            confidence += min(0.15, 0.06 * len(govt_matches))
            category_scores['GOVT_SCHEME'] = len(govt_matches)
        
        # Check insurance patterns (weight: 0.15)
        insurance_matches = self._check_patterns(text, self.compiled_insurance)
        if insurance_matches:
            detected_patterns.extend([f"insurance:{m}" for m in insurance_matches])
            confidence += min(0.15, 0.06 * len(insurance_matches))
            category_scores['INSURANCE'] = len(insurance_matches)
        
        # Check common scam phrases (weight: 0.10)
        phrase_matches = self._check_phrases(text_lower)
        if phrase_matches:
            detected_patterns.extend([f"phrase:{m}" for m in phrase_matches])
            confidence += min(0.10, 0.05 * len(phrase_matches))
        
        # Extract suspicious keywords found
        suspicious_keywords = self._extract_suspicious_keywords(text_lower)
        
        # Determine scam category (using category scores + pattern analysis)
        scam_category = self._determine_category(detected_patterns, category_scores)
        
        # Consider conversation history for context boost
        if conversation_history:
            history_boost = self._analyze_history(conversation_history)
            confidence = min(1.0, confidence + history_boost)
        
        # Normalize confidence
        confidence = min(1.0, confidence)
        
        # Determine if scam (threshold: 0.25 - slightly lower to catch more scams)
        is_scam = confidence >= 0.25
        
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
        # Check single words
        words = re.findall(r'\b\w+\b', text_lower)
        for word in words:
            if word in self.SUSPICIOUS_KEYWORDS:
                found.append(word)
        # Check multi-word keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if ' ' in keyword and keyword in text_lower:
                found.append(keyword)
        return list(set(found))
    
    def _determine_category(self, detected_patterns: List[str], category_scores: Dict = None) -> str:
        """Determine the category of scam based on detected patterns and scores"""
        
        # First check category-specific scores (most reliable)
        if category_scores:
            best_category = max(category_scores, key=category_scores.get, default=None)
            if best_category and category_scores[best_category] >= 2:
                return best_category
        
        # Fallback to pattern analysis
        pattern_str = ' '.join(detected_patterns).lower()
        
        # Check specific categories first (more specific → less specific)
        if any(p in pattern_str for p in ['income_tax', 'tax refund', 'itr', 'tds']):
            return "INCOME_TAX"
        elif any(p in pattern_str for p in ['electricity', 'power', 'disconnect']):
            return "ELECTRICITY_BILL"
        elif any(p in pattern_str for p in ['customs', 'parcel', 'courier', 'shipment']):
            return "CUSTOMS_PARCEL"
        elif any(p in pattern_str for p in ['tech_support', 'virus', 'malware', 'infected']):
            return "TECH_SUPPORT"
        elif any(p in pattern_str for p in ['job_scam', 'hiring', 'vacancy', 'work from home']):
            return "JOB_SCAM"
        elif any(p in pattern_str for p in ['investment', 'crypto', 'bitcoin', 'trading']):
            return "CRYPTO_INVESTMENT"
        elif any(p in pattern_str for p in ['loan', 'pre-approved', 'disburse', 'sanction']):
            return "LOAN_SCAM"
        elif any(p in pattern_str for p in ['insurance', 'policy', 'premium', 'lic']):
            return "INSURANCE"
        elif any(p in pattern_str for p in ['govt_scheme', 'yojana', 'subsidy', 'scheme']):
            return "GOVT_SCHEME"
        elif 'upi' in pattern_str or 'payment' in pattern_str:
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
            text = msg.get('text', '') if isinstance(msg, dict) else str(msg)
            sender = msg.get('sender', '') if isinstance(msg, dict) else str(msg)
            
            # Only analyze scammer messages
            if str(sender).lower() == 'scammer':
                # Quick keyword check (avoid recursion)
                text_lower = text.lower()
                scam_words = ['urgent', 'blocked', 'verify', 'otp', 'pin', 'upi', 
                              'payment', 'transfer', 'click', 'link', 'prize', 'winner',
                              'loan', 'tax', 'customs', 'parcel', 'virus', 'insurance',
                              'electricity', 'job', 'investment', 'crypto']
                matches = sum(1 for w in scam_words if w in text_lower)
                if matches >= 2:
                    boost += 0.05
        
        return min(0.20, boost)
    
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
