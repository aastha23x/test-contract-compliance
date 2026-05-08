"""
run_pipeline.py — Master Compliance Audit Pipeline
Runs all 3 layers in sequence:
  Layer 1: compliance_agent.py  (AI violation scan)
  Layer 2: framework_mapper.py  (framework mapping)
  Layer 3: report_generator.py  (HTML dashboard)
"""
import sys
import time
import subprocess
from datetime import datetime

STEPS = [
    {
        "name":   "Layer 1 — AI Compliance Scan",
        "module": "app.services.compliance_agent",
        "desc":   "Fetching MongoDB data & running Azure GPT-4o analysis...",
    },
    {
        "name":   "Layer 2 — Framework Mapper",
        "module": "app.services.framework_mapper",
        "desc":   "Mapping violations to ISO27001 / SOC2 / HIPAA / GDPR...",
    },
    {
        "name":   "Layer 3 — HTML Dashboard",
        "module": "app.services.report_generator",
        "desc":   "Generating HTML compliance dashboard...",
    },
]

def banner(text, char="="):
    line = char * 70
    print(f"\n{line}")
    print(f"   {text}")
    print(line)

def run_step(step, index, total):

    banner(f"[{index}/{total}] {step['name']}")
    print(f"   {step['desc']}\n")

    start = time.time()
    result = subprocess.run(
        [sys.executable, "-m", step["module"]],
        capture_output=False
    )
    elapsed = time.time() - start

    if result.returncode == 0:
        print(f"\n✅ {step['name']} completed in {elapsed:.1f}s")
        return True
    else:
        print(f"\n❌ {step['name']} FAILED (exit code {result.returncode})")
        return False

def main():
    banner("AVIRAT.AI — FULL COMPLIANCE AUDIT PIPELINE", "═")
    print(f"   Started at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("   Mode       : Webhook Scan → Framework Map → Report Generation")
    print("═" * 70)

    results   = {}
    total     = len(STEPS)
    all_passed = True

    for i, step in enumerate(STEPS, 1):
        ok = run_step(step, i, total)
        results[step["name"]] = "✅ PASSED" if ok else "❌ FAILED"
        if not ok:
            all_passed = False
            print(f"\n⚠️  Pipeline halted at step {i} due to failure.")
            print("   Fix the error above and re-run.")
            break

    # Final summary
    banner("PIPELINE SUMMARY", "═")
    for name, status in results.items():
        print(f"   {status}  {name}")

        print("\n🎉 Full pipeline completed successfully!")
        print("   📄 violation_report.json")
        print("   📄 framework_mapping_report.json")
        print("   🌐 compliance_dashboard.html  ← open in your browser")
    else:
        print("\n⚠️  Pipeline completed with errors.")

    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
