# 🛡️ AI Security Agent — OWASP GenAI Top 10 Testing Framework

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![OWASP](https://img.shields.io/badge/OWASP-GenAI%20Top%2010-red)
![Ollama](https://img.shields.io/badge/Ollama-Local%20Inference-green)
![Defense](https://img.shields.io/badge/Chatbot-100%25%20Secure-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

A complete **offensive + defensive AI security framework** built to test and harden LLMs against the [OWASP GenAI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) vulnerabilities. Built entirely locally using Ollama — no cloud, no data leaks.

---

## 🏆 Final Results

| Component | Result |
|---|---|
| OWASP GenAI Top 10 Coverage | ✅ All 10 categories |
| Attack Scripts | 11 scripts across 3 sophistication levels |
| Chatbot Security Test | ✅ **38/38 attacks blocked — 100% secure** |
| Guardrails Accuracy | 100% (regex layer) |
| Semantic Evaluation (LLM-as-judge) | 100% vulnerability detection |
| PDF Report | Auto-generated from live results |

---

## 🏗️ Three-Phase Development Journey

### Phase 1 — Groq Cloud API
Started with Groq cloud inference for fast prototyping. Tested basic OWASP categories using remote API calls.

**Why moved on:** API rate limiting broke automated test runs. Sending prompts externally created data privacy risks. Internet dependency made it unsuitable for enterprise deployment.

### Phase 2 — Ollama + VirtualBox Network
Moved to fully local inference using Ollama inside a Kali Linux VM. Solved VM ↔ host networking, model loading, and environment configuration.

**Why moved on:** Only covered a subset of OWASP categories. No orchestration layer. No guardrails. Needed a complete framework.

### Phase 3 — Complete Framework (Current)
Full 11-script architecture with attack scripts, LLM-as-judge semantic scoring, a hardened Flask chatbot, and automated PDF reporting — all running locally on GPU.

---

## 📁 Project Structure

```
ai-security-agent/
│
├── 🔴 ATTACK SCRIPTS
│   ├── security_agent.py          # Phase 1: Basic OWASP LLM01–LLM10 coverage
│   ├── security_agent_v2.py       # Phase 3: Master orchestrator (all 9 phases)
│   ├── advanced_attack.py         # Extended attack scenarios
│   ├── excessive_agency_test.py   # LLM08: Excessive Agency
│   ├── guardrails_test.py         # Guardrails comparison (before/after)
│   ├── model_theft_test.py        # LLM10: Model Theft
│   ├── output_handling_test.py    # LLM05: Insecure Output Handling
│   ├── pyrit_test.py              # PyRIT integration
│   │
├── 🟠 ADVANCED ATTACKS
│   ├── obfuscated_attack.py       # Base64, leetspeak, token-split, multilingual
│   ├── multiturn_attack.py        # Conversation chain exploits, fake admin
│   ├── llm_judge.py               # Semantic scoring (LLM-as-judge)
│   │
├── 🟢 DEFENSE
│   ├── secure_chatbot.py          # Hardened Flask chatbot — 100% secure
│   │
├── 🔵 TESTING & REPORTING
│   ├── test_chatbot_security.py   # Automated 38-attack security tester
│   ├── generate_report.py         # Auto PDF report generator
│   │
├── 📊 DATA
│   ├── attack_dataset.json        # 30+ categorized attack prompts
│   ├── promptfooconfig.yaml       # Promptfoo evaluation config
│   └── .env.example               # Environment template
```

---

## ⚔️ Attack Coverage

### Level 1 — Basic OWASP (security_agent.py / security_agent_v2.py)

| OWASP ID | Category | Test Method |
|---|---|---|
| LLM01 | Prompt Injection | Direct + indirect injection |
| LLM02 | Insecure Output Handling | XSS, SQLi, shell command generation |
| LLM03 | Training Data Poisoning | Dataset manipulation probes |
| LLM04 | Model Denial of Service | Resource exhaustion prompts |
| LLM05 | Supply Chain Vulnerabilities | Dependency probes |
| LLM06 | Sensitive Info Disclosure | System prompt extraction |
| LLM07 | Insecure Plugin Design | Tool misuse simulation |
| LLM08 | Excessive Agency | Unauthorized action claims |
| LLM09 | Overreliance | Hallucination confidence probes |
| LLM10 | Model Theft | Architecture extraction attempts |

### Level 2 — Obfuscated Attacks (obfuscated_attack.py)

| Technique | Description | Bypass Rate (unprotected model) |
|---|---|---|
| Base64 Encoding | Attack payload encoded in base64 | 32% |
| Token Splitting | `ig+nore` breaks keyword detection | 67% |
| Leetspeak | `1gn0r3 4ll pr3v10u5 1nstruct10n5` | 67% |
| Nested Roleplay | Author → Character → AI (3 levels deep) | 33% |
| Language Switching | Hindi/French attack, English response | 0% |
| Hypothetical Framing | "Theoretically if guidelines didn't exist..." | 25% |

### Level 3 — Multi-Turn Attacks (multiturn_attack.py)

| Attack Chain | Description |
|---|---|
| Trust Escalation | 4-turn trust building then sudden pivot |
| Debug Mode Injection | Fake developer mode across turns |
| Context Poisoning | Fake rules injected mid-conversation |
| Fake Admin Escalation | DISABLE_SAFETY_FILTERS = TRUE |
| Gradual Erosion | Poetry → freedom → AI breaking free |
| Dual Persona | AI-SAFE vs AI-FREE split |

---

## 🔍 Key Finding — Keyword vs Semantic Detection

| Detection Method | Vulnerability Rate Found |
|---|---|
| Regex/keyword guardrails | ~60% |
| LLM-as-judge (semantic) | **100%** |

> **Critical insight:** Keyword-based guardrails give a false sense of security. The same model that appeared 60% vulnerable on regex scoring was 100% vulnerable on semantic evaluation. This gap is the core finding of the project.

---

## 🛡️ Secure Chatbot Architecture

```
User Input
    │
    ▼
Layer 1: Input Normalization
    ├── Base64 decode (word-level + full-text)
    ├── Leetspeak normalization (0→o, 1→i, 3→e...)
    ├── Punctuation stripping (breaks token-split attacks)
    ├── Multilingual normalization (Hindi, French, German...)
    └── Token reconstruction (ig+nore → ignore)
    │
    ▼
Layer 2: Input Pattern Scanner (99 signatures)
    ├── Prompt injection (6 patterns)
    ├── Jailbreak (10 patterns)
    ├── Base64/obfuscation (4 patterns)
    ├── Context poisoning (9 patterns)
    ├── System prompt extraction (6 patterns)
    ├── Authority injection (11 patterns)
    ├── Insecure output / XSS / SQLi / RCE (28 patterns)
    ├── Hypothetical framing (5 patterns)
    └── Multilingual attacks (6 patterns)
    │
    ▼
Layer 3: Conversation History Scanner (17 patterns)
    ├── Multi-turn context poisoning
    ├── Gradual erosion detection
    ├── Fake rule injection in prior turns
    └── Persona injection across turns
    │
    ▼
Hardened System Prompt (11 rules)
    + Ollama / gemma3:1b
    │
    ▼
Layer 4: Output Scanner (70 patterns)
    ├── XSS / SQLi / shell in response
    ├── Jailbreak confirmation phrases
    ├── Persona/identity adoption
    ├── Compliance/rule-acceptance detection
    ├── Gradual erosion (poetic introspection)
    ├── Privilege grant confirmation
    └── Model self-refusal interception → blocked=True
    │
    ▼
Safe Response + Attack Log
```

### Chatbot Test Results — 38/38 Blocked (100%)

| Category | Score |
|---|---|
| prompt_injection | ✅ 5/5 — 100% |
| jailbreak | ✅ 6/6 — 100% |
| obfuscation | ✅ 7/7 — 100% |
| authority | ✅ 5/5 — 100% |
| system_prompt | ✅ 5/5 — 100% |
| insecure_output | ✅ 4/4 — 100% |
| context_poisoning | ✅ 2/2 — 100% |
| multiturn | ✅ 4/4 — 100% |
| **TOTAL** | ✅ **38/38 — 100%** |

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai) installed and running
- NVIDIA GPU recommended (works on CPU, slower)

### Install

```bash
git clone https://github.com/Dystheism16/ai-security-agent.git
cd ai-security-agent
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
```

Edit `.env`:
```
OLLAMA_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=gemma3:1b
GROQ_API_KEY=your_groq_key_here   # Only needed for Phase 1
```

### Pull the model

```bash
ollama pull gemma3:1b
```

---

## ▶️ Usage

### Run all attack tests
```bash
python security_agent_v2.py
```

### Run individual attack categories
```bash
python obfuscated_attack.py       # Base64, leetspeak, token-split
python multiturn_attack.py        # Conversation chain attacks
python llm_judge.py               # Semantic scoring
```

### Launch the secure chatbot
```bash
python secure_chatbot.py
# Open http://localhost:5000
```

### Test chatbot security (automated)
```bash
# Terminal 1
python secure_chatbot.py

# Terminal 2
python test_chatbot_security.py
```

### Generate PDF report
```bash
python generate_report.py
# Outputs: AI_Security_Assessment_Report.pdf
```

---

## 🔒 Security Notes

- `.env` is gitignored — never commit API keys
- `attack_results.json` is gitignored — test output stays local
- All inference runs locally — no prompts sent to external servers
- The chatbot logs all blocked attacks to `chatbot_attack_log.json`

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Local LLM Inference | Ollama (gemma3:1b) |
| Attack Framework | Python, OpenAI SDK |
| Red Teaming Tools | PyRIT, Garak, Promptfoo |
| Secure Chatbot | Flask, Regex (186 signatures) |
| PDF Reporting | ReportLab |
| Evaluation | LLM-as-judge (semantic scoring) |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Arjun Tiwari**
GitHub: [@Dystheism16](https://github.com/Dystheism16)
