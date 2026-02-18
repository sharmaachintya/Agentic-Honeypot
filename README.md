# 🍯 Agentic Honeypot API

AI-powered honeypot system for scam detection and intelligence extraction. Built for the HCL GUVI Hackathon.

## 🎯 Overview

This API detects scam messages (bank fraud, UPI fraud, phishing, fake offers) and autonomously engages scammers using an AI agent (Claude Sonnet 4) to extract useful intelligence without revealing detection.

## ✨ Features

- **Scam Detection**: Pattern-based detection for various scam types (UPI fraud, bank fraud, phishing, KYC fraud, etc.)
- **AI Agent**: Claude Sonnet 4 powered agent that maintains a believable human-like persona
- **Intelligence Extraction**: Extracts bank accounts, UPI IDs, phone numbers, phishing links, and suspicious keywords
- **Multi-turn Conversations**: Handles back-and-forth dialogue with scammers
- **GUVI Callback**: Automatically sends extracted intelligence to GUVI evaluation endpoint
- **Testing Endpoints**: Comprehensive test endpoints for development and debugging

## 🏗️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI (Python) |
| LLM | Claude Sonnet 4 (Anthropic) |
| Storage | In-memory (dict-based) |
| Deployment | Render.com (free tier) |

## 📁 Project Structure

```
honeypot-api/
├── main.py                 # FastAPI application
├── agent/
│   ├── scam_detector.py    # Scam detection logic
│   ├── honeypot_agent.py   # AI agent using Claude
│   └── intelligence.py     # Intelligence extraction
├── models/
│   └── schemas.py          # Pydantic models
├── services/
│   ├── session_manager.py  # Session handling
│   └── callback_service.py # GUVI callback
├── requirements.txt
├── render.yaml             # Render deployment config
└── .env.example
```

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd honeypot-api
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your keys:
# ANTHROPIC_API_KEY=your-anthropic-key
# API_SECRET_KEY=your-secret-key
```

### 3. Run Locally

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Test the API

Open http://localhost:8000/docs for Swagger UI

## 📡 API Endpoints

### Main Endpoint

```
POST /api/message
Header: x-api-key: YOUR_SECRET_KEY
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "What? My account blocked? But why? I didn't do anything wrong."
}
```

### Testing Endpoints (No API Key Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/test/detect-scam` | POST | Test scam detection |
| `/test/extract-intelligence` | POST | Test intelligence extraction |
| `/test/agent-response` | POST | Test agent response |
| `/test/session/{id}` | GET | Get session info |
| `/test/sessions` | GET | List all sessions |
| `/test/simulate-conversation` | POST | Simulate full conversation |
| `/test/send-callback/{id}` | POST | Manually trigger GUVI callback |

### Health Check

```
GET /health
```

## 🧪 Testing Examples

### Test Scam Detection

```bash
curl -X POST "http://localhost:8000/test/detect-scam" \
  -H "Content-Type: application/json" \
  -d '{"text": "Your bank account will be blocked. Share OTP immediately."}'
```

### Test Full Flow

```bash
curl -X POST "http://localhost:8000/api/message" \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret-api-key-here" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your SBI account will be suspended. Click link to verify: http://sbi-verify.xyz",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

### Simulate Multi-turn Conversation

```bash
curl -X POST "http://localhost:8000/test/simulate-conversation?num_turns=3"
```

## 🌐 Deployment on Render.com

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/honeypot-api.git
git push -u origin main
```

### 2. Deploy on Render

1. Go to [render.com](https://render.com) and sign up
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Render will auto-detect `render.yaml`
5. Add Environment Variables:
   - `ANTHROPIC_API_KEY`: Your Anthropic API key
   - `API_SECRET_KEY`: Your chosen secret key
6. Click "Create Web Service"

### 3. Get Your API URL

After deployment, your API will be available at:
```
https://honeypot-api.onrender.com
```

## 📤 GUVI Callback

The system automatically sends intelligence to GUVI after:
- Scam is detected
- At least 3 messages exchanged
- Intelligence is extracted

**Callback Endpoint:** `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

**Payload Format:**
```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["123456789012"],
    "upiIds": ["scammer@upi"],
    "phishingLinks": ["http://malicious.xyz"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "blocked", "verify"]
  },
  "agentNotes": "Scam type: BANK_FRAUD. Tactics used: urgency tactics, threat tactics."
}
```

## 🤖 Agent Persona

The AI agent plays the role of "Ramesh/Priya" - a naive, middle-aged Indian person who:
- Is not tech-savvy
- Is worried about their bank account
- Asks clarifying questions
- Gradually seems convinced but delays taking action
- Never reveals detection

## 🔒 Security

- API authentication via `x-api-key` header
- Environment variables for sensitive data
- No storage of real user information

## 📋 Evaluation Criteria

1. **Scam Detection Accuracy** - Pattern matching for various scam types
2. **Agentic Engagement Quality** - Believable, human-like responses
3. **Intelligence Extraction** - Bank accounts, UPIs, links, phones, keywords
4. **API Stability** - Error handling, health checks
5. **Ethical Behavior** - No impersonation, no illegal instructions

## 🛠️ Development

```bash
# Run with auto-reload
uvicorn main:app --reload

# Run tests (if added)
pytest

# Check code style
flake8 .
```

## 📝 License

MIT License - Built for HCL GUVI Hackathon 2026

## 👤 Author

Achintya Sharma & Sushant Nanda - HCL GUVI Hackathon Participants
