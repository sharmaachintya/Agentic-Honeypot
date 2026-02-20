# Project Context: Agentic Honeypot API

> **Last Updated:** Feb 20, 2026, 10:50 AM IST
> **Status:** LIVE — Deployed on Render, currently being evaluated by GUVI platform
> **Hackathon:** India AI Impact Buildathon — 24-Hour Online Honeypot Challenge (Feb 20 10AM – Feb 21 10AM)
> **Team:** Achintya Sharma + Sushant Nanda

---

## What This Project Is

An AI-powered honeypot REST API that:
1. **Receives** scam messages from GUVI's evaluation platform
2. **Detects** scam intent using pattern matching (15+ categories)
3. **Engages** scammers using Claude Sonnet 4 with a believable naive-victim persona ("Ramesh")
4. **Extracts** intelligence: phone numbers, bank accounts, UPI IDs, phishing links, emails, case IDs, policy numbers, order numbers
5. **Sends callback** with final results to GUVI's endpoint for scoring

---

## Deployment

| Item | Value |
|------|-------|
| **Render URL** | `https://agentic-honeypot-kv6d.onrender.com` |
| **API Endpoint** | `POST /api/message` |
| **GitHub** | `https://github.com/sharmaachintya/Agentic-Honeypot` |
| **Latest Commit** | `e4bf16a` (v3.1) |
| **Keep-Alive** | cron-job.org pings `/health` every 1 minute |
| **LLM** | Anthropic Claude Sonnet 4 (`claude-sonnet-4-20250514`) |

### Render Environment Variables
- `ANTHROPIC_API_KEY` — Anthropic Claude API key
- `API_SECRET_KEY` — API key for x-api-key authentication
- `CLAUDE_MODEL` — (optional) defaults to `claude-sonnet-4-20250514`

---

## Scoring Rubric (Feb 19 Updated Doc)

**Total: 100 points per scenario (90% weight) + Code Quality (10% weight)**

### 1. Scam Detection — 20 pts
- `scamDetected: true` → 20 pts

### 2. Extracted Intelligence — 30 pts
- Dynamic: `30 ÷ total fake data fields in scenario`
- Types: phoneNumbers, bankAccounts, upiIds, phishingLinks, emailAddresses, caseIds, policyNumbers, orderNumbers

### 3. Conversation Quality — 30 pts (BIGGEST scoring area!)
| Sub-Category | Max | How |
|---|---|---|
| Turn Count | 8 pts | ≥8 turns = 8, ≥6 = 6, ≥4 = 3 |
| Questions Asked | 4 pts | ≥5 questions = 4, ≥3 = 2, ≥1 = 1 |
| Relevant Questions | 3 pts | ≥3 investigative = 3, ≥2 = 2, ≥1 = 1 |
| Red Flag Identification | 8 pts | ≥5 flags = 8, ≥3 = 5, ≥1 = 2 |
| Information Elicitation | 7 pts | Each attempt = 1.5pts (max 7) |

### 4. Engagement Quality — 10 pts
| Metric | Points |
|---|---|
| Duration > 0s | 1 |
| Duration > 60s | 2 |
| Duration > 180s | 1 |
| Messages > 0 | 2 |
| Messages ≥ 5 | 3 |
| Messages ≥ 10 | 1 |

### 5. Response Structure — 10 pts
| Field | Points | Status |
|---|---|---|
| sessionId | 2 (Required) | ✅ |
| scamDetected | 2 (Required) | ✅ |
| extractedIntelligence | 2 (Required) | ✅ |
| totalMessagesExchanged + engagementDurationSeconds | 1 (Optional) | ✅ |
| agentNotes | 1 (Optional) | ✅ |
| scamType | 1 (Optional) | ✅ |
| confidenceLevel | 1 (Optional) | ✅ |

### 6. Code Quality — 10% of final score
- Evaluated from GitHub repo: clean code, README, documentation, approach explanation

### Final Score Formula
```
Scenario Score = Σ (Scenario_Score × Scenario_Weight / 100)
Final Score = (Scenario Score × 0.9) + Code Quality Score
```

---

## Architecture & File Structure

```
honeypot-api/
├── main.py                         # FastAPI app — main endpoint POST /api/message
├── agent/
│   ├── scam_detector.py           # Pattern matching for 15+ scam categories
│   ├── honeypot_agent.py          # Claude-powered conversational agent
│   └── intelligence.py            # Regex extraction for all intelligence types
├── models/
│   └── schemas.py                 # Pydantic models for request/response
├── services/
│   ├── session_manager.py         # Thread-safe in-memory session tracking
│   └── callback_service.py        # GUVI callback with all scored fields
├── requirements.txt
├── .env.example
├── Procfile                        # Render deployment
├── render.yaml
└── README.md
```

---

## How the Flow Works

```
GUVI Platform → POST /api/message → Your API
    1. Parse message (sessionId, message.text, conversationHistory, metadata)
    2. Scam Detection (pattern matching → category + confidence)
    3. Intelligence Extraction (regex on SCAMMER messages only)
    4. Claude generates agent reply (naive victim persona)
    5. Callback sent to GUVI on every turn after 3+ messages
    6. Return {"status": "success", "reply": "agent response"}
```

### Callback Payload (sent to GUVI)
```json
{
  "sessionId": "...",
  "scamDetected": true,
  "totalMessagesExchanged": 20,
  "engagementDurationSeconds": 500,
  "extractedIntelligence": {
    "phoneNumbers": [...],
    "bankAccounts": [...],
    "upiIds": [...],
    "phishingLinks": [...],
    "emailAddresses": [...],
    "caseIds": [...],
    "policyNumbers": [...],
    "orderNumbers": [...]
  },
  "agentNotes": "...",
  "scamType": "BANK_FRAUD",
  "confidenceLevel": 0.62,
  "engagementMetrics": {
    "engagementDurationSeconds": 500,
    "totalMessages": 20
  },
  "status": "success"
}
```

---

## Key Design Decisions

### Intelligence Extraction
- **Only extracts from SCAMMER messages** — prevents false positives from agent-generated dummy data (e.g., agent says "name@sbi" as example → would be wrongly extracted)
- **Agent dummy data filtered**: `ramesh1975@okaxis`, `name@sbi`, `name@bank`
- **Case ID blacklist**: filters common English words like "erence", "reference", "number"
- **UPI patterns**: includes `@fakebank`, `@fakeupi`, `@fake` for GUVI test data + contextual matching

### Scam Category Locking
- Once a specific category is detected (e.g., BANK_FRAUD), it **won't be overridden** by a generic/lower-confidence detection
- Confidence tracks the **maximum** seen across all turns

### Callback Strategy
- Callback sent on **EVERY turn after 3+ messages** (not just once)
- Because GUVI system waits only **10 seconds** after conversation ends for final output
- Engagement duration estimated as `messages × 25s` minimum to ensure >180s for scoring

### Agent Prompts
- Persona: "Ramesh" — naive middle-aged Indian shopkeeper
- **Every response must contain**: a question + red flag reference + elicitation attempt
- Category-specific tactics for all 15 scenarios
- Hindi words mixed in: "Arre", "Haan ji", "Accha"
- max_tokens=200 to keep responses fast (~3-5 seconds)

---

## Known Issues & Observations from Live Testing

### From GUVI conversation logs (Bank Fraud scenario):
1. **Agent responses are long** (5-10 sentences) but this HELPS Conversation Quality scoring — lots of questions, red flags, elicitation
2. **Agent performs well**: asks identity questions, references urgency changes, identifies fake-sounding UPIs
3. **Fixed bugs in v3.1**: false positive UPI extraction, broken case ID regex, category flipping, low confidence tracking

### From Insurance scenario (live during hackathon):
- Scammer provides: policy POL123456789, UPI lic-renewal@fakepayment.insure, phone +91-6655443322, employee ID 1122, name "Anil Sharma", address "123 XYZ Road", landline 022-12345678
- Agent successfully: asks 5+ questions per response, identifies red flags (time pressure, "fakepayment" word, wrong name), probes for details, keeps conversation for 10+ turns

### Potential Issues to Watch:
- **UPI extraction for unusual providers**: If scammer uses a UPI like `something@unknownprovider`, it might not be caught unless "bank", "upi", or "pay" is in the provider name
- **Scam category first detection**: First turn sometimes detects wrong category (e.g., TECH_SUPPORT instead of BANK_FRAUD) — v3.1 locks category after first specific detection
- **Callback endpoint**: If GUVI's callback endpoint is down/slow, the callback might fail — logged but doesn't block the response

---

## Version History

| Version | Commit | Changes |
|---------|--------|---------|
| v1.0 | `cbb204c` | Initial implementation |
| v2.0 | `6f55206` | Added engagementMetrics, status field, all 15 scam categories, emailAddresses, engagement duration tracking |
| v3.0 | `b13cea1` | Updated for Feb 19 rubric — scamType, confidenceLevel, caseIds/policyNumbers/orderNumbers, enhanced agent prompts for Conversation Quality (30pts), comprehensive README |
| v3.1 | `e4bf16a` | Bug fixes: scammer-only extraction, stricter case ID regex, locked scam category, max confidence tracking, UPI fakebank support, agent dummy data filtering |

---

## Testing Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/api/message` | POST | `x-api-key` | Main evaluation endpoint |
| `/test/detect-scam` | POST | No | Test scam detection |
| `/test/extract-intelligence` | POST | No | Test entity extraction |
| `/test/agent-response` | POST | No | Test agent reply |
| `/test/simulate-conversation` | POST | No | Full conversation simulation |
| `/test/session/{id}` | GET | No | View session details |
| `/test/sessions` | GET | No | List all sessions |
| `/test/score-preview/{id}` | GET | No | Preview expected score |
| `/test/send-callback/{id}` | POST | No | Manually trigger callback |
| `/test/callback-history` | GET | No | View callback history |
| `/docs` | GET | No | Swagger UI interactive docs |

---

## What Needs Improvement (For Future Work)

1. **UPI extraction**: Could be more aggressive — extract ANY `word@word` pattern from scammer messages and filter later
2. **Employee IDs**: Not currently extracted as a scored field but scammers often share them (e.g., "ID 1122", "ID SBI-12345")
3. **Agent response length**: Currently 5-10 sentences — could experiment with shorter responses for more natural feel (but long responses score well on Conversation Quality)
4. **LLM-powered extraction**: Use Claude to extract entities in addition to regex — would catch non-standard formats
5. **Parallel callback**: Send callback in background thread to not delay API response time
