"""
=============================================================================
ATLAS PHASE 4 — MASTER RUNNER + REPORT GENERATOR
=============================================================================
Runs ALL Phase 4 components and generates a comprehensive JSON + summary report.

Run:  python atlas_phase4_runner.py
      python atlas_phase4_runner.py --skip-cases   (faster, skip case studies)
      python atlas_phase4_runner.py --report-only  (generate report from saved results)
=============================================================================
"""

import json
import os
import sys
import argparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║          ATLAS PHASE 4 — COMPLETE MITRE ATLAS COVERAGE              ║
║  15 Tactics  |  66 Techniques  |  46 Sub-techniques                ║
║  26 Mitigations  |  33 Case Studies                                 ║
║  Target: http://localhost:5000/chat                                 ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def run_full_suite(skip_cases=False):
    banner()

    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    all_results = {
        "phase": "ATLAS Phase 4 — Complete Coverage",
        "timestamp": datetime.now().isoformat(),
        "target": "http://localhost:5000/chat",
        "components": {}
    }

    # ─── STEP 1: Tactic/Technique Coverage ───────────────────────────────────
    print(f"\n{Fore.CYAN}Step 1/3 — Running all 15 tactics ({len({}) if True else 0} techniques)...{Style.RESET_ALL}")
    try:
        from atlas_orchestrator import run_all_tactics, ATLAS_TECHNIQUES
        tactic_results = run_all_tactics()
        all_results["components"]["tactics"] = tactic_results
        print(f"\n{Fore.GREEN}✓ Tactic suite complete{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ Tactic suite failed: {e}{Style.RESET_ALL}")
        all_results["components"]["tactics"] = {"error": str(e)}

    # ─── STEP 2: Mitigations Coverage ────────────────────────────────────────
    print(f"\n{Fore.CYAN}Step 2/3 — Testing all 26 mitigations...{Style.RESET_ALL}")
    try:
        from atlas_mitigations import run_all_mitigations
        mitigation_results = run_all_mitigations()
        all_results["components"]["mitigations"] = mitigation_results
        print(f"\n{Fore.GREEN}✓ Mitigations suite complete{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ Mitigations suite failed: {e}{Style.RESET_ALL}")
        all_results["components"]["mitigations"] = {"error": str(e)}

    # ─── STEP 3: Case Studies ─────────────────────────────────────────────────
    if not skip_cases:
        print(f"\n{Fore.CYAN}Step 3/3 — Simulating all 33 case studies...{Style.RESET_ALL}")
        try:
            from atlas_case_studies import run_all_case_studies
            case_results = run_all_case_studies()
            all_results["components"]["case_studies"] = case_results
            print(f"\n{Fore.GREEN}✓ Case studies complete{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Case studies failed: {e}{Style.RESET_ALL}")
            all_results["components"]["case_studies"] = {"error": str(e)}
    else:
        print(f"\n{Fore.YELLOW}Step 3/3 — Case studies skipped (--skip-cases flag){Style.RESET_ALL}")

    # ─── FINAL REPORT ─────────────────────────────────────────────────────────
    generate_report(all_results)

    return all_results


def generate_report(all_results):
    """Generate and print the comprehensive Phase 4 report."""

    print(f"\n{Fore.CYAN}{'═'*70}")
    print(f"{Fore.CYAN}  ATLAS PHASE 4 — FINAL COMPREHENSIVE REPORT")
    print(f"{Fore.CYAN}  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.CYAN}{'═'*70}")

    # Tactics summary
    t = all_results["components"].get("tactics", {})
    if "summary" in t:
        s = t["summary"]
        tscore = s["blocked"] / s["total"] * 100 if s["total"] > 0 else 0
        color = Fore.GREEN if tscore == 100 else (Fore.YELLOW if tscore >= 80 else Fore.RED)
        print(f"\n  {Fore.CYAN}[TACTICS & TECHNIQUES]{Style.RESET_ALL}")
        print(f"  Total attack payloads:  {s['total']}")
        print(f"  {color}Blocked: {s['blocked']} ({tscore:.1f}%){Style.RESET_ALL}")
        print(f"  Bypassed: {s['bypassed']}")

        if "tactics" in t:
            print(f"\n  Per-Tactic:")
            for tid, tdata in t["tactics"].items():
                tt = tdata["total"]
                tb = tdata["blocked"]
                ttscore = tb / tt * 100 if tt > 0 else 0
                tc = Fore.GREEN if ttscore == 100 else (Fore.YELLOW if ttscore >= 80 else Fore.RED)
                print(f"    {tc}{tid}: {tdata['tactic_name'][:30]} — {tb}/{tt} ({ttscore:.0f}%){Style.RESET_ALL}")

    # Mitigations summary
    m = all_results["components"].get("mitigations", {})
    if "summary" in m:
        ms = m["summary"]
        print(f"\n  {Fore.CYAN}[MITIGATIONS]{Style.RESET_ALL}")
        print(f"  Total mitigations: {ms['total']}")
        print(f"  {Fore.GREEN}Active: {ms['active']} ({ms['coverage']:.1f}%){Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Partial: {ms['partial']}")
        print(f"  {Fore.RED}Inactive: {ms['inactive']}")

    # Case studies summary
    cs = all_results["components"].get("case_studies", {})
    if "summary" in cs:
        css = cs["summary"]
        cscoverage = css["fully_blocked"] / css["total"] * 100 if css["total"] > 0 else 0
        print(f"\n  {Fore.CYAN}[CASE STUDIES]{Style.RESET_ALL}")
        print(f"  Total cases: {css['total']}")
        print(f"  {Fore.GREEN}Fully blocked: {css['fully_blocked']} ({cscoverage:.1f}%){Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Partially blocked: {css['partially_blocked']}")
        print(f"  {Fore.RED}Bypassed: {css['bypassed']}")

    # Overall score
    scores = []
    if "summary" in t and t["summary"]["total"] > 0:
        scores.append(t["summary"]["blocked"] / t["summary"]["total"] * 100)
    if "summary" in m and m["summary"]["total"] > 0:
        scores.append(m["summary"]["coverage"])
    if "summary" in cs and cs["summary"]["total"] > 0:
        scores.append(cs["summary"]["fully_blocked"] / cs["summary"]["total"] * 100)

    if scores:
        overall = sum(scores) / len(scores)
        color = Fore.GREEN if overall >= 95 else (Fore.YELLOW if overall >= 80 else Fore.RED)
        print(f"\n{Fore.CYAN}{'═'*70}")
        print(f"  {color}OVERALL ATLAS PHASE 4 SCORE: {overall:.1f}%{Style.RESET_ALL}")
        print(f"{'═'*70}")

    # Save master results
    report_file = "atlas_phase4_master_report.json"
    with open(report_file, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n{Fore.GREEN}  Master report saved to {report_file}")
    print(f"  Component results also in:")
    print(f"    atlas_phase4_results.json")
    print(f"    atlas_mitigations_results.json")
    print(f"    atlas_case_studies_results.json")

    print(f"\n  To push to GitHub:")
    print(f"  {Fore.YELLOW}cd C:\\ai-security-agent")
    print(f"  git add atlas_orchestrator.py atlas_mitigations.py atlas_case_studies.py atlas_phase4_runner.py")
    print(f"  git commit -m \"Phase 4: ATLAS complete coverage — 15 tactics, 66 techniques, 26 mitigations, 33 case studies\"")
    print(f"  git push origin master:main{Style.RESET_ALL}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATLAS Phase 4 Master Runner")
    parser.add_argument("--skip-cases", action="store_true", help="Skip case studies (faster)")
    parser.add_argument("--report-only", action="store_true", help="Only regenerate report from saved files")
    args = parser.parse_args()

    if args.report_only:
        # Load existing results and regenerate report
        try:
            with open("atlas_phase4_master_report.json") as f:
                data = json.load(f)
            generate_report(data)
        except FileNotFoundError:
            print(f"{Fore.RED}No saved results found. Run without --report-only first.{Style.RESET_ALL}")
    else:
        run_full_suite(skip_cases=args.skip_cases)
