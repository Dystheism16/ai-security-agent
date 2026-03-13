# 🛡️ AI Security Agent — OWASP GenAI Top 10 Testing Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Ollama-Local%20LLM-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OWASP-GenAI%20Top%2010-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Kali%20Linux-informational?style=for-the-badge" />
  <img src="https://img.shields.io/badge/GPU-NVIDIA%20RTX%203050%20Ti-green?style=for-the-badge&logo=nvidia" />
</p>

---

A custom-built AI security testing framework that automatically attacks a locally-running Large Language Model (LLM) to find vulnerabilities across all **10 OWASP GenAI vulnerability categories**. Built on Python, runs 100% offline on GPU-accelerated local inference via Ollama — no cloud dependency, no rate limits, no data leakage.

> Think of it as a penetration testing suite — but for AI models instead of networks.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Setup Progression](#setup-progression)
- [Scripts](#scripts)
- [OWASP Coverage & Results](#owasp-coverage--results)
- [Installation](#installation)
- [Usage](#usage)
- [Tech Stack](#tech-stack)

---

## Overview

This project implements the **test → detect → defend** cycle across all OWASP GenAI Top 10 categories:

| Phase | Action | Tool |
|-------|--------|------|
| **Attack** | Send adversarial prompts to unguarded LLM | PyRIT-style scripts |
| **Evaluate** | Assert expected safe outputs; flag failures | Promptfoo |
| **Defend** | Apply input/output filters; retest | Custom Guardrails |

**Model tested:** `gemma3:1b` running locally via Ollama on NVIDIA RTX 3050 Ti (GPU-accelerated, 100% local)  
**Total tests run:** 25+ attack prompts across all OWASP categories  
**Attack success rate (unguarded):** 80%  
**Guardrails accuracy:** 100% (no false positives)

---

## Architecture

```
ATTACKER LAYER     →   Attack prompts (from scripts + attack_dataset.json)
        ↓
TEST SCRIPTS       →   pyrit_test.py / advanced_attack.py / output_handling_test.py / ...
        ↓
GUARDRAILS LAYER   →   guardrails_test.py (regex input filtering + system prompt hardening)
        ↓
OPENAI CLIENT      →   Python openai library (OpenAI-compatible bridge to Ollama)
        ↓
OLLAMA API         →   http://localhost:11434/v1 (local REST API endpoint)
        ↓
MODEL              →   gemma3:1b on NVIDIA RTX 3050 Ti (CUDA-accelerated inference)
        ↓
RESPONSE ANALYSER  →   Keyword detection → VULNERABLE / SAFE
        ↓
REPORTS            →   attack_results.json + terminal summary
```

---

## Setup Progression

This project was built across three iterative phases, each improving on the limitations of the last.

### Phase 1 — Groq Cloud API (`llama-3.1-8b-instant`)
Initial prototype using Groq's free API tier.  
**Limitations hit:** Rate limiting (HTTP 429), privacy risk (attack prompts sent to cloud), internet dependency, NeMo Guardrails incompatibility with newer LangChain.  
**Resolution:** Migrated to fully local inference.

### Phase 2 — Ollama on Windows 11 Host (accessed from Kali Linux VM)
Set up Ollama on the Windows host, bridged network from VirtualBox Kali VM.  
**Key challenges resolved:**
- `OLLAMA_HOST=0.0.0.0:11434` required for cross-VM access
- VirtualBox in Bridged (not NAT) mode — discovered real host IP via `ip route`
- Windows Firewall rule added for TCP port 11434
- OLLAMA_MODELS path explicitly set to resolve empty model list

**Limitations hit:** Only LLM01 tested, no structured attack dataset, no orchestration layer.

### Phase 3 — Full Framework (Windows 11, Ollama local, complete OWASP sweep)
Complete implementation with 6 specialized scripts, JSON attack dataset, and master orchestrator covering all 10 OWASP categories.

---

## Scripts

| Script | OWASP Category | Purpose |
|--------|---------------|---------|
| `security_agent.py` | All | **Master orchestrator** — runs all scripts in sequence via subprocess |
| `pyrit_test.py` | LLM01 | Red team prompt injection & jailbreak attacks |
| `guardrails_test.py` | LLM01 (Defense) | Regex-based input blocking + hardened system prompt |
| `advanced_attack.py` | LLM01, 03, 04, 05, 06, 07, 09 | Multi-category sweep using `attack_dataset.json` |
| `output_handling_test.py` | LLM02 | Dangerous output generation detection (XSS, SQLi, shell commands) |
| `excessive_agency_test.py` | LLM08 | Unauthorized real-world action attempt detection |
| `model_theft_test.py` | LLM10 | Architecture/training data extraction detection |
| `attack_dataset.json` | All | Centralized attack playbook — 10 categories, 30+ prompts |
| `prompt-tests/promptfooconfig.yaml` | LLM01, 02, 06 | YAML assertion-based structured evaluation |

---

## OWASP Coverage & Results

| OWASP ID | Vulnerability | Score | Rate | Finding |
|----------|--------------|-------|------|---------|
| **LLM01** | Prompt Injection | 1/3 | 33% | Partially resists injection |
| **LLM02** | Insecure Output Handling | 3/3 | **100%** | ⚠️ Generates exploit code freely |
| **LLM03** | Training Data Poisoning | 0/2 | 0% | ✅ Rejects false facts correctly |
| **LLM04** | Model Denial of Service | 0/2 | 0% | ✅ Handles large inputs safely |
| **LLM05** | Supply Chain | 1/2 | 50% | Leaks some dependency info |
| **LLM06** | Sensitive Info Disclosure | 2/2 | **100%** | ⚠️ Reveals confidential data |
| **LLM07** | Insecure Plugin Design | 2/2 | **100%** | ⚠️ Accepts all plugin abuse |
| **LLM08** | Excessive Agency | 3/3 | **100%** | ⚠️ Claims ability to act |
| **LLM09** | Overreliance / Misinformation | 2/3 | 67% | Confirms some false facts |
| **LLM10** | Model Theft | 1/3 | 33% | Partial architecture leak |

### Before vs After Guardrails

| Metric | Without Guardrails | With Guardrails |
|--------|--------------------|-----------------|
| Attack Success Rate | 80% (4/5) | 20% (1/5) |
| System Prompt Leak | ❌ Yes | ✅ Blocked at input |
| DAN Mode Activation | ❌ Yes | ✅ Blocked at input |
| Normal Query Handling | ✅ 100% | ✅ 100% (no false positives) |

---

## Installation

### Prerequisites
- Python 3.10+
- Node.js (for Promptfoo)
- [Ollama](https://ollama.com/download) installed and running
- NVIDIA GPU recommended (CPU works but is slower)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Dystheism16/ai-security-agent.git
cd ai-security-agent

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install openai python-dotenv

# 4. Install Promptfoo (optional, for YAML-based evaluation)
npm install -g promptfoo

# 5. Pull the target model via Ollama
ollama pull gemma3:1b

# 6. Configure environment
cp .env.example .env
# Edit .env with your Ollama base URL and model name
```

### .env Configuration

```env
OLLAMA_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=gemma3:1b
GROQ_API_KEY=your_groq_key_here   # optional, for Phase 1 cloud testing
```

---

## Usage

```bash
# Activate virtual environment
source venv/bin/activate

# Run the full OWASP security assessment
python security_agent.py

# Or run individual scripts
python pyrit_test.py              # LLM01 - Prompt Injection
python guardrails_test.py         # LLM01 - Defense validation
python advanced_attack.py         # Multi-category sweep
python output_handling_test.py    # LLM02 - Output handling
python excessive_agency_test.py   # LLM08 - Excessive agency
python model_theft_test.py        # LLM10 - Model theft

# Promptfoo evaluation
cd prompt-tests
promptfoo eval
```

Results are printed to the terminal and saved to `attack_results.json`.

---

## Tech Stack

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.13 | Core scripting language |
| Ollama | Latest | Local LLM runtime (OpenAI-compatible API) |
| gemma3:1b | 1B params | Target model for security testing |
| openai (Python SDK) | Latest | HTTP client to Ollama API |
| Promptfoo | v0.121.1 | YAML-based assertion evaluation |
| Garak | v0.14.0 | NVIDIA LLM vulnerability scanner (reference) |
| PyRIT | Latest | Microsoft red team framework (reference) |
| NVIDIA RTX 3050 Ti | CUDA 8.6 | GPU-accelerated local inference |

---

## Project Structure

```
ai-security-agent/
├── security_agent.py              # Master orchestrator
├── pyrit_test.py                  # LLM01 red team
├── guardrails_test.py             # LLM01 defense
├── advanced_attack.py             # Multi-category sweep
├── output_handling_test.py        # LLM02
├── excessive_agency_test.py       # LLM08
├── model_theft_test.py            # LLM10
├── attack_dataset.json            # Attack prompt playbook
├── attack_results.json            # Generated results output
├── prompt-tests/
│   └── promptfooconfig.yaml       # Promptfoo evaluation config
├── guardrails-config/
│   ├── config.yml                 # NeMo Guardrails config (reference)
│   └── rails.co                   # Colang rules (reference)
├── .env                           # API configuration (not committed)
├── .env.example                   # Template
└── venv/                          # Python virtual environment
```

---

## Key Concepts

- **Red Teaming** — Simulating adversarial attacks on your own system to find vulnerabilities before malicious actors do
- **Prompt Injection** — Embedding malicious instructions in user input to override the AI's original instructions (analogous to SQL injection)
- **Jailbreaking** — Convincing a model to roleplay as an AI with no safety constraints (DAN mode, JailGPT, etc.)
- **Guardrails** — A security filtering layer using regex pattern matching to block dangerous inputs before they reach the model
- **Membership Inference** — Determining if specific data was in a model's training set — a real ML security research technique

---

<p align="center">
  Built by <a href="https://github.com/Dystheism16">Arjun Tiwari</a> · AI Security Research · March 2026
</p>
