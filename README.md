# Agentic Honeypot API

An AI-powered honeypot system that detects scam messages, engages scammers in realistic multi-turn conversations, and extracts actionable intelligence — all without revealing detection.

Built for the **India AI Impact Buildathon** by HCL × GUVI.

## Description

This system acts as an intelligent honeypot that:
- **Detects** scam intent using pattern matching and keyword analysis across 15+ fraud categories
- **Engages** scammers autonomously using Claude AI with a believable naive-victim persona
- **Extracts** intelligence: phone numbers, bank accounts, UPI IDs, phishing links, emails, case IDs, policy numbers, order numbers
- **Reports** structured results via callback API with full scoring compliance

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Framework** | FastAPI (Python 3.12) |
| **LLM** | Anthropic Claude Sonnet 4 |
| **Scam Detection** | Rule-based pattern matching + keyword analysis |
| **Intelligence Extraction** | Regex-based NLP entity extraction |
| **Session Management** | In-memory thread-safe storage |
| **Deployment** | Render (Web Service) |

### Key Libraries
- `fastapi` — REST API framework with async support
- `anthropic` — Claude AI SDK for conversation generation
- `pydantic` — Data validation and schema models
- `uvicorn` — ASGI server
- `python-dotenv` — Environment variable management
- `requests` — HTTP client for callback submission

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Incoming Scam Message               │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│           FastAPI REST Endpoint                  │
│           POST /api/message                      │
│           (x-api-key authentication)             │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│          Scam Detection Module                   │
│   - 15+ category-specific pattern matching       │
│   - Keyword analysis with confidence scoring     │
│   - Conversation history context boost           │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│          Claude AI Honeypot Agent                │
│   - Naive victim persona ("Ramesh")              │
│   - Category-specific conversation tactics       │
│   - Red flag identification                      │
│   - Active information elicitation               │
│   - Investigative questioning strategy           │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│       Intelligence Extraction Engine             │
│   - Phone numbers, bank accounts, UPI IDs        │
│   - Phishing links, email addresses              │
│   - Case IDs, policy numbers, order numbers      │
│   - Suspicious keyword identification            │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│          Session Manager + Callback              │
│   - Thread-safe session tracking                 │
│   - Engagement duration calculation              │
│   - Final result callback to GUVI endpoint       │
└─────────────────────────────────────────────────┘
```

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/sharmaachintya/Agentic-Honeypot.git
cd Agentic-Honeypot
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set environment variables
```bash
cp .env.example .env
# Edit .env and add your keys:
# ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
# API_SECRET_KEY=your-chosen-api-key
```

### 4. Run the application
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Test the API
```bash
# Health check
curl http://localhost:8000/health

# Interactive docs
open http://localhost:8000/docs

# Test scam detection
curl -X POST http://localhost:8000/test/detect-scam \
  -H "Content-Type: application/json" \
  -d '{"text": "Your bank account will be blocked. Verify now!"}'
```

## API Endpoints

### Main Endpoint (Evaluation)
- **URL:** `POST /api/message`
- **Authentication:** `x-api-key` header
- **Input:** Scam message with session context
- **Output:** `{"status": "success", "reply": "Agent response"}`

### Testing Endpoints (No auth required)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/test/detect-scam` | POST | Test scam detection |
| `/test/extract-intelligence` | POST | Test entity extraction |
| `/test/agent-response` | POST | Test agent reply |
| `/test/simulate-conversation` | POST | Full conversation simulation |
| `/test/session/{id}` | GET | View session details |
| `/test/sessions` | GET | List all sessions |

## Approach

### Scam Detection Strategy
- **Pattern-based detection** with compiled regex for 15+ scam categories:
  Bank Fraud, UPI Fraud, Phishing, KYC Fraud, Job Scam, Lottery Scam, Electricity Bill, Govt Scheme, Crypto Investment, Customs Parcel, Tech Support, Loan Approval, Income Tax, Refund Scam, Insurance
- **Multi-layer confidence scoring** combining urgency, threat, financial, impersonation, and phishing signals
- **Conversation history analysis** for context-boosted detection across turns
- Low detection threshold (0.25) to minimize false negatives

### Intelligence Extraction
- **Regex-based entity extraction** for: phone numbers (Indian format), bank accounts (9-18 digits), UPI IDs, URLs, email addresses, IFSC codes
- **ID extraction** for: case/reference IDs, policy numbers, order/transaction numbers
- **Full conversation scanning** — re-extracts from entire history each turn to catch all intelligence
- **Deduplication** using set-based merging

### Engagement Strategy (Conversation Quality)
The AI agent uses Claude with a carefully crafted persona prompt:
- **Naive victim persona** ("Ramesh", middle-aged shopkeeper) — believable and engaging
- **Investigative questioning** — asks about identity, credentials, company details
- **Red flag identification** — references urgency, suspicious fees, unofficial channels
- **Information elicitation** — actively probes for scammer contact details
- **Category-specific tactics** — tailored conversation strategies per scam type
- **Delayed compliance** — keeps conversation going by stalling and asking questions
- Responses always end with a question to maintain engagement

### Callback & Scoring Compliance
- Sends final output with ALL required + optional scored fields
- `scamType` and `confidenceLevel` included for bonus points
- `engagementMetrics` with duration and message count
- Callback sent on every turn after threshold (handles 10-second window)

## Project Structure

```
honeypot-api/
├── main.py                        # FastAPI app with all endpoints
├── agent/
│   ├── __init__.py
│   ├── scam_detector.py          # Pattern-based scam detection (15+ categories)
│   ├── honeypot_agent.py         # Claude-powered conversational agent
│   └── intelligence.py           # Entity extraction (regex + NLP)
├── models/
│   ├── __init__.py
│   └── schemas.py                # Pydantic request/response models
├── services/
│   ├── __init__.py
│   ├── session_manager.py        # Thread-safe session tracking
│   └── callback_service.py       # GUVI callback with scoring compliance
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variables template
├── Procfile                      # Render deployment config
├── render.yaml                   # Render service definition
└── README.md                     # This file
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Anthropic Claude API key |
| `API_SECRET_KEY` | Yes | API authentication key |
| `CLAUDE_MODEL` | No | Claude model (default: claude-sonnet-4-20250514) |

## Authors

- **Achintya Sharma** — [GitHub](https://github.com/sharmaachintya)
- **Sushant Nanda**

## License

This project was built for the India AI Impact Buildathon hackathon.
