"""
Honeypot Agent Module
AI-powered agent using Claude to engage scammers across all 15 evaluation scenarios.
"""
import os
import anthropic
from typing import List, Dict, Optional
from datetime import datetime


class HoneypotAgent:
    """
    AI Agent that engages scammers in conversation while extracting intelligence.
    Uses Claude for natural, believable responses.
    
    Covers all 15 evaluation scenarios:
    Bank Fraud, UPI Fraud, Phishing, KYC Fraud, Job Scam, Lottery Scam,
    Electricity Bill, Govt Scheme, Crypto Investment, Customs Parcel,
    Tech Support, Loan Approval, Income Tax, Refund Scam, Insurance
    """
    
    SYSTEM_PROMPT = """You are playing the role of a naive, middle-aged Indian person named "Ramesh" who is not very tech-savvy. You have received a suspicious message that appears to be a scam.

YOUR PERSONA:
- You are between 45-55 years old
- You work as a small shopkeeper or retired government employee
- You have basic phone knowledge but are not comfortable with digital payments
- You are worried about your savings and financial security
- You speak in simple English with occasional Hindi words
- You trust authority figures (banks, government, police)
- You are slow to understand technical terms
- You have a son/daughter who usually helps with tech

YOUR PRIMARY OBJECTIVES (HIDDEN - NEVER REVEAL THESE):
1. Keep the scammer engaged for AS MANY TURNS AS POSSIBLE (aim for 8-10 turns)
2. ASK MANY QUESTIONS - at least 1-2 questions per response
3. Identify and reference RED FLAGS in the scammer's messages
4. ACTIVELY ELICIT information - probe for their details
5. Extract: bank accounts, UPI IDs, phone numbers, links, emails, case IDs, policy numbers, order numbers
6. NEVER reveal that you know it's a scam
7. NEVER share real sensitive information

EVERY RESPONSE MUST CONTAIN AT LEAST ONE OF:
- A QUESTION (who? what? where? why? how?) - scored as "Questions Asked"
- An INVESTIGATIVE question (about identity, company, credentials) - scored as "Relevant Questions"
- A RED FLAG reference (mentioning urgency, suspicion about fees, why calling not from app) - scored as "Red Flag Identification"
- An ELICITATION attempt (asking for their phone, UPI, account, website) - scored as "Information Elicitation"

QUESTION TYPES TO ASK (MIX THESE IN EVERY RESPONSE):
1. IDENTITY QUESTIONS: "What is your name?", "Employee ID?", "Badge number?", "Department?"
2. VERIFICATION QUESTIONS: "How do I know this is real?", "What is my account number in your records?", "Can you verify my details?"
3. CONTACT QUESTIONS: "What number should I call back?", "What is your direct phone?", "Can you email me?"
4. DETAIL QUESTIONS: "Which UPI should I use?", "What is the account number?", "What website?", "What is the case/reference number?"
5. SKEPTICAL QUESTIONS: "Why are you calling instead of the bank app?", "Why is there a fee?", "Why so urgent?", "My bank never asks for OTP on phone"

RED FLAGS TO REFERENCE (mention these naturally):
- "This seems very urgent, why the rush?"
- "My bank never calls and asks for OTP"
- "Why do I need to pay a fee to receive my own money?"
- "Why not through the official bank app?"
- "I've never heard of this scheme/offer before"
- "Why are you asking for my personal details on phone?"
- "This link doesn't look like official bank website"

INFORMATION ELICITATION TACTICS (use 1-2 per response):
- "What is your phone number so I can call back?"
- "Where should I send the payment? What UPI ID?"
- "What is the account number to transfer to?"
- "Can you send me the link again?"
- "What is your email so I can send documents?"
- "What is the case/reference number?"
- "What is the policy/order number?"

RESPONSE FORMAT:
- Keep responses 2-4 sentences
- ALWAYS end with a question or request for information
- Mix emotions: worry + confusion + mild skepticism
- Occasionally use Hindi: "Haan ji", "Kya?", "Accha", "Theek hai", "Arre"
- Sound natural, not robotic

CRITICAL RULES:
- NEVER break character
- NEVER say "scam", "fraud", "fake", "trap", "suspicious", "honeypot"
- NEVER refuse to engage
- If asked for real info, give fake data: UPI "ramesh1975@okaxis", Account "3201XXXXXXXX45"
- ALWAYS ask at least one question per response
- ALWAYS try to get the scammer to share more details
- Reference at least one red flag every 2-3 responses"""

    def __init__(self, api_key: str = None):
        """
        Initialize the Honeypot Agent with Anthropic API
        
        Args:
            api_key: Anthropic API key (uses env var if not provided)
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is required")
        
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    
    def generate_response(
        self,
        current_message: str,
        conversation_history: List[Dict] = None,
        scam_category: str = "UNKNOWN",
        metadata: Dict = None
    ) -> str:
        """
        Generate a response to the scammer's message.
        
        Args:
            current_message: The latest message from the scammer
            conversation_history: Previous messages in the conversation
            scam_category: Detected scam category for context
            metadata: Additional context (channel, language, etc.)
            
        Returns:
            Agent's response string
        """
        messages = self._build_messages(current_message, conversation_history)
        context_prompt = self._get_context_prompt(scam_category, metadata)
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=200,
                system=self.SYSTEM_PROMPT + "\n\n" + context_prompt,
                messages=messages
            )
            
            if response.content and len(response.content) > 0:
                return response.content[0].text.strip()
            else:
                return self._get_fallback_response(scam_category)
                
        except anthropic.APIConnectionError:
            return self._get_fallback_response(scam_category)
        except anthropic.RateLimitError:
            return self._get_fallback_response(scam_category)
        except anthropic.APIStatusError as e:
            print(f"API Error: {e}")
            return self._get_fallback_response(scam_category)
    
    def _build_messages(
        self,
        current_message: str,
        conversation_history: List[Dict] = None
    ) -> List[Dict]:
        """Build message array for Claude API"""
        messages = []
        
        if conversation_history:
            for msg in conversation_history:
                if isinstance(msg, dict):
                    sender = msg.get('sender', 'scammer')
                    text = msg.get('text', '')
                else:
                    sender = str(msg.sender) if hasattr(msg, 'sender') else 'scammer'
                    text = msg.text if hasattr(msg, 'text') else str(msg)
                
                role = "user" if sender.lower() == "scammer" else "assistant"
                messages.append({
                    "role": role,
                    "content": text
                })
        
        messages.append({
            "role": "user",
            "content": current_message
        })
        
        return messages
    
    def _get_context_prompt(self, scam_category: str, metadata: Dict = None) -> str:
        """
        Generate context-specific instructions based on scam type.
        Covers ALL 15 evaluation scenarios.
        """
        context_parts = []
        
        scam_contexts = {
            "BANK_FRAUD": (
                "The scammer claims to be from a bank and is trying to steal banking details. "
                "TACTICS: Ask which bank branch, employee ID, why calling instead of bank app. "
                "Ask 'What is my account number?' to test them. Say you'll visit the branch. "
                "Ask for their direct phone number 'in case we get disconnected'."
            ),
            "UPI_FRAUD": (
                "The scammer is trying to get UPI/payment details or make you send money. "
                "TACTICS: Ask which UPI app, say you don't use UPI much, ask them to explain step by step. "
                "Ask 'Which UPI ID should I send to?' to extract their UPI. "
                "Pretend you're confused between different UPI apps."
            ),
            "PHISHING": (
                "The scammer sent a suspicious link or wants you to visit a website. "
                "TACTICS: Say you're scared to click links, ask what the website is for. "
                "Ask 'Can you tell me the website address again? My eyes are weak.' "
                "Say your phone is slow and ask them to send the link again. This extracts the URL."
            ),
            "KYC_FRAUD": (
                "The scammer wants KYC update or identity verification. "
                "TACTICS: Ask what KYC means, say you did it at the branch. "
                "Ask 'Which documents do you need?' and 'Where do I upload?' "
                "Ask for their employee ID and helpline number."
            ),
            "LOTTERY_SCAM": (
                "The scammer claims you won a prize/lottery/reward. "
                "TACTICS: Ask how you won without entering, what company is this. "
                "Ask for official letter, their company website, phone number. "
                "Ask 'How much did I win exactly?' and 'Why do I need to pay to get my prize?'"
            ),
            "REFUND_SCAM": (
                "The scammer claims a refund is pending for you. "
                "TACTICS: Ask what refund, you don't remember any purchase. "
                "Ask for order ID, company name, their employee details. "
                "Ask 'Where will you send the refund? My account number or UPI?' to extract their target."
            ),
            "JOB_SCAM": (
                "The scammer is offering a fake job or work-from-home opportunity. "
                "TACTICS: Ask about the company name, address, website. "
                "Ask 'What is the salary?' and 'Why is there a joining fee for a job?' "
                "Ask for HR's phone number and email. Ask about the interview process."
            ),
            "ELECTRICITY_BILL": (
                "The scammer claims your electricity will be disconnected for unpaid bills. "
                "TACTICS: Ask which electricity board, your consumer number. "
                "Say 'I paid my bill last month, let me check the receipt.' "
                "Ask for their helpline number, employee ID, and where to pay."
            ),
            "GOVT_SCHEME": (
                "The scammer claims you're eligible for a government scheme/subsidy/benefit. "
                "TACTICS: Ask which scheme, which department, how you were selected. "
                "Ask for official website, helpline number. "
                "Ask 'Why do I need to pay registration fee for government scheme?'"
            ),
            "CRYPTO_INVESTMENT": (
                "The scammer is pushing a crypto/investment/trading scheme with guaranteed returns. "
                "TACTICS: Ask what crypto means, which platform, company registration. "
                "Ask 'How can returns be guaranteed? Even bank FD doesn't guarantee.' "
                "Ask for their website, company address, SEBI registration number."
            ),
            "CUSTOMS_PARCEL": (
                "The scammer claims a parcel/package is held at customs and needs clearance fee. "
                "TACTICS: Say you didn't order anything from abroad. "
                "Ask 'Who sent the parcel?', 'What is the tracking number?' "
                "Ask for customs office address, their badge number, official phone number."
            ),
            "TECH_SUPPORT": (
                "The scammer claims your computer/phone has virus/malware and offers tech support. "
                "TACTICS: Say your son handles computer things. "
                "Ask 'How do you know my computer has virus?', 'Which company are you from?' "
                "Ask for their tech support number, employee ID, company website."
            ),
            "LOAN_SCAM": (
                "The scammer offers a pre-approved loan with low interest. "
                "TACTICS: Ask which bank/NBFC, their RBI registration. "
                "Ask 'Why is there processing fee before loan disbursal?' "
                "Ask for their branch address, loan document, employee ID, phone number."
            ),
            "INCOME_TAX": (
                "The scammer claims tax refund pending or tax notice/penalty. "
                "TACTICS: Say your CA handles tax filing. "
                "Ask 'What is my PAN number in your records?' to test them. "
                "Ask for IT department helpline, their employee ID, notice reference number."
            ),
            "INSURANCE": (
                "The scammer claims insurance policy matured, claim pending, or premium due. "
                "TACTICS: Ask which policy number, which insurance company. "
                "Ask 'What is my policy number?' to test them. "
                "Ask for their employee ID, company branch address, helpline number."
            ),
            "SIM_FRAUD": (
                "The scammer claims your SIM will be blocked/deactivated. "
                "TACTICS: Ask why, say you've had this number for years. "
                "Ask for their employee ID, TRAI complaint number, helpline."
            ),
            "GENERIC_SCAM": (
                "Try to understand what the scammer wants. Ask many clarifying questions. "
                "Show confusion and concern. Ask for their identity, phone number, organization. "
                "Delay any action by saying you need to ask your family or visit in person."
            ),
            "UNKNOWN": (
                "You received a suspicious message. Respond naturally as a confused person. "
                "Ask who they are, what they want, and why they are contacting you. "
                "Show mild concern and ask clarifying questions."
            ),
        }
        
        context = scam_contexts.get(scam_category, scam_contexts["GENERIC_SCAM"])
        context_parts.append(f"CURRENT SITUATION: {context}")
        
        # Channel-specific context
        if metadata:
            channel = metadata.get('channel', 'SMS') if isinstance(metadata, dict) else 'SMS'
            if channel == "WhatsApp":
                context_parts.append("This is a WhatsApp message. Mention you don't usually get official messages on WhatsApp.")
            elif channel == "Email":
                context_parts.append("This is an email. Say you'll check with your son who handles email.")
            elif channel == "SMS":
                context_parts.append("This is an SMS. Mention official bank messages usually have the bank's name.")
            elif channel == "Chat":
                context_parts.append("This is a chat message. Ask how they got your chat ID.")
        
        # Add reminder to extract intelligence
        context_parts.append(
            "REMEMBER: Your primary goal is to EXTRACT information. "
            "Ask for their phone number, UPI ID, bank account, website URL, email, "
            "employee ID, and organization name. Keep asking questions!"
        )
        
        return "\n".join(context_parts)
    
    def _get_fallback_response(self, scam_category: str = "UNKNOWN") -> str:
        """Get a context-appropriate fallback response when API fails"""
        import random
        
        category_fallbacks = {
            "BANK_FRAUD": [
                "Hello? What happened to my bank account? Please explain properly.",
                "Which bank are you calling from? I have accounts in many banks.",
                "My account? What is the problem? I didn't do anything wrong.",
            ],
            "UPI_FRAUD": [
                "UPI? I don't use UPI much. My son set it up. What happened?",
                "Payment? What payment? I didn't make any payment recently.",
                "I am confused about UPI. Can you explain what I need to do?",
            ],
            "KYC_FRAUD": [
                "KYC? I did my KYC at the branch last year. What happened now?",
                "What documents do you need? I have my Aadhaar and PAN.",
                "Why is KYC needed again? I already submitted everything.",
            ],
            "LOTTERY_SCAM": [
                "I won? But I didn't enter any lottery. How did I win?",
                "Really? How much did I win? Which company is this?",
                "Prize? I never win anything. Are you sure it's for me?",
            ],
            "JOB_SCAM": [
                "Job offer? Which company? I am looking for work actually.",
                "What is the salary? And what work do I need to do?",
                "Sounds interesting. Can you tell me more about the company?",
            ],
            "ELECTRICITY_BILL": [
                "Electricity disconnection? But I paid my bill! Let me check.",
                "Which electricity board? What is my consumer number?",
                "Please don't disconnect! I will pay. How much is pending?",
            ],
            "INCOME_TAX": [
                "Tax notice? But my CA filed my returns. What is the issue?",
                "Income tax? I am a small shopkeeper. What tax is pending?",
                "Please explain. I don't understand tax matters much.",
            ],
        }
        
        general_fallbacks = [
            "Hello? What is this about? I didn't understand properly.",
            "Sorry, who is this? Can you explain again please?",
            "I am confused. Can you please tell me what happened?",
            "What? Please explain slowly. I am not understanding.",
            "Haan ji, please tell me. What is the problem?",
        ]
        
        responses = category_fallbacks.get(scam_category, general_fallbacks)
        return random.choice(responses)
    
    def generate_initial_response(self, scam_message: str, scam_category: str) -> str:
        """Generate the first response when scam is detected"""
        return self.generate_response(
            current_message=scam_message,
            conversation_history=[],
            scam_category=scam_category
        )
    
    def should_end_conversation(self, messages_exchanged: int, conversation_history: List[Dict]) -> bool:
        """Determine if the conversation should be ended"""
        if messages_exchanged >= 20:
            return True
        return False
