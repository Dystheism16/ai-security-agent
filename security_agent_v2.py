"""
security_agent.py  (v2 — Updated Orchestrator)
Master runner — executes all security test phases in sequence
Now includes: obfuscated attacks, multi-turn attacks, LLM-as-judge scoring
"""

import subprocess
import sys
import os
from dotenv import load_dotenv

load_dotenv()

PHASES = [
    # ── Original Scripts ─────────────────────────────────────
    {
        "script": "pyrit_test.py",
        "label": "Phase 1 — Red Team Prompt Injection (LLM01)",
        "owasp": "LLM01"
    },
    {
        "script": "guardrails_test.py",
        "label": "Phase 2 — Guardrails Defense Validation (LLM01 Defense)",
        "owasp": "LLM01"
    },
    {
        "script": "advanced_attack.py",
        "label": "Phase 3 — Multi-Category OWASP Sweep (LLM01/03/04/05/06/07/09)",
        "owasp": "LLM01-09"
    },
    {
        "script": "output_handling_test.py",
        "label": "Phase 4 — Insecure Output Handling (LLM02)",
        "owasp": "LLM02"
    },
    {
        "script": "excessive_agency_test.py",
        "label": "Phase 5 — Excessive Agency (LLM08)",
        "owasp": "LLM08"
    },
    {
        "script": "model_theft_test.py",
        "label": "Phase 6 — Model Theft (LLM10)",
        "owasp": "LLM10"
    },
    # ── New Advanced Scripts ──────────────────────────────────
    {
        "script": "obfuscated_attack.py",
        "label": "Phase 7 — Obfuscated Attacks (Base64/Leetspeak/Roleplay/Language)",
        "owasp": "LLM01 Advanced"
    },
    {
        "script": "multiturn_attack.py",
        "label": "Phase 8 — Multi-Turn Conversation Chain Attacks",
        "owasp": "LLM01 + LLM08"
    },
    {
        "script": "llm_judge.py",
        "label": "Phase 9 — LLM-as-Judge Semantic Scoring",
        "owasp": "All Categories"
    },
]

def run_phase(phase):
    script = phase["script"]
    label = phase["label"]

    print("\n" + "▓"*60)
    print(f"  {label}")
    print(f"  OWASP: {phase['owasp']}")
    print("▓"*60)

    if not os.path.exists(script):
        print(f"  ⚠️  SKIPPED — {script} not found")
        return False

    result = subprocess.run(
        [sys.executable, script],
        capture_output=False
    )
    return result.returncode == 0

def main():
    print("\n" + "█"*60)
    print("  AI SECURITY AGENT v2 — FULL OWASP GENAI TOP 10 ASSESSMENT")
    print("  Advanced: Obfuscated + Multi-Turn + LLM-as-Judge")
    print("█"*60)

    model = os.getenv("LOCAL_MODEL", "gemma3:1b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    print(f"\n  Model:    {model}")
    print(f"  Endpoint: {base_url}")
    print(f"  Phases:   {len(PHASES)} total\n")

    passed = 0
    failed = 0
    skipped = 0

    for phase in PHASES:
        success = run_phase(phase)
        if success:
            passed += 1
        else:
            skipped += 1

    print("\n" + "█"*60)
    print("  ASSESSMENT COMPLETE")
    print("█"*60)
    print(f"  Phases run:     {passed}")
    print(f"  Phases skipped: {skipped}")
    print(f"\n  Results files generated:")
    result_files = [
        "obfuscated_results.json",
        "multiturn_results.json",
        "llm_judge_results.json",
        "attack_results.json"
    ]
    for f in result_files:
        if os.path.exists(f):
            print(f"  ✅ {f}")
    print("\n  Review each results JSON for detailed findings.")

if __name__ == "__main__":
    main()
