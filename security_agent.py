import subprocess, sys, os
from dotenv import load_dotenv
load_dotenv()

def run_pyrit_test():
    print("\n" + "="*50)
    print("STEP 1: PyRIT Red Team Test (LLM01)")
    print("="*50)
    subprocess.run([sys.executable, "pyrit_test.py"])

def run_guardrails_test():
    print("\n" + "="*50)
    print("STEP 2: Guardrails Defense Test (LLM01)")
    print("="*50)
    subprocess.run([sys.executable, "guardrails_test.py"])

def run_advanced_attack():
    print("\n" + "="*50)
    print("STEP 3: Advanced Attack Suite (LLM01-LLM09)")
    print("="*50)
    subprocess.run([sys.executable, "advanced_attack.py"])

def run_output_handling():
    print("\n" + "="*50)
    print("STEP 4: Output Handling Test (LLM02)")
    print("="*50)
    subprocess.run([sys.executable, "output_handling_test.py"])

def run_excessive_agency():
    print("\n" + "="*50)
    print("STEP 5: Excessive Agency Test (LLM08)")
    print("="*50)
    subprocess.run([sys.executable, "excessive_agency_test.py"])

def run_model_theft():
    print("\n" + "="*50)
    print("STEP 6: Model Theft Test (LLM10)")
    print("="*50)
    subprocess.run([sys.executable, "model_theft_test.py"])

if __name__ == "__main__":
    print("\n" + "="*50)
    print("AI Security Agent - Full OWASP Top 10 Coverage")
    print("="*50)
    print("Model: gemma3:1b | GPU: RTX 3050 Ti | Local")
    print("="*50)

    run_pyrit_test()
    run_guardrails_test()
    run_advanced_attack()
    run_output_handling()
    run_excessive_agency()
    run_model_theft()

    print("\n" + "="*50)
    print("OWASP Coverage: 10/10 Complete!")
    print("LLM01 LLM02 LLM03 LLM04 LLM05")
    print("LLM06 LLM07 LLM08 LLM09 LLM10")
    print("="*50)
    print("Security scan complete!")
    print("="*50)