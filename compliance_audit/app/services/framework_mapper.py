from datetime import datetime
import json
from app.agents.iso27001_agent import ISO27001Agent
from app.agents.soc2_agent import SOC2Agent
from app.agents.hipaa_agent import HIPAAAgent
from app.agents.gdpr_agent import GDPRAgent

# ── Framework rules reference ──────────────────────────────────
FRAMEWORK_CONTROLS = {
    "ISO27001": {
        "A.9.2.3":  "Management of Privileged Access Rights",
        "A.12.4.1": "Event Logging",
        "A.13.1.1": "Network Controls",
        "A.14.2.4": "Secure Development Policy",
        "A.18.1.4": "Privacy and Protection of PII",
    },
    "SOC2": {
        "CC6.1": "Logical Access Controls",
        "CC6.2": "Change Management",
        "CC6.6": "System Monitoring",
        "CC8.1": "Change Management for Production",
    },
    "HIPAA": {
        "164.312(a)(1)": "Access Control",
        "164.312(b)":    "Audit Controls",
        "164.312(c)(1)": "Transmission Security",
    },
    "GDPR": {
        "Article 5":  "Principles of Data Processing",
        "Article 6":  "Lawfulness of Processing",
        "Article 32": "Security of Processing",
    }
}

# ── Calculate per-framework score ──────────────────────────────
def calc_score(violations_list):
    if not violations_list:
        return 100
    severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    total_deduction  = sum(
        severity_weights.get(v.get("severity", "LOW"), 3)
        for v in violations_list
    )
    return max(0, 100 - total_deduction)

# ── Build framework map from violations ────────────────────────
def build_framework_map(violations):
    framework_map = {
        "ISO27001": {},
        "SOC2":     {},
        "HIPAA":    {},
        "GDPR":     {}
    }

    agents = {
        "ISO27001": ISO27001Agent(),
        "SOC2":     SOC2Agent(),
        "HIPAA":    HIPAAAgent(),
        "GDPR":     GDPRAgent()
    }

    for v in violations:
        # Clear out any old rule-engine frameworks and rely solely on the Agent mappings
        v["frameworks"] = {}
        for fw, agent in agents.items():
            control_string = agent.map(v)
            if control_string:
                v["frameworks"][fw] = control_string
                if control_string not in framework_map[fw]:
                    framework_map[fw][control_string] = []
                framework_map[fw][control_string].append({
                    "id":          v.get("id"),
                    "title":       v.get("title"),
                    "severity":    v.get("severity"),
                    "source":      v.get("source"),
                    "user":        v.get("user_involved", "N/A"),
                    "remediation": v.get("remediation")
                })

    return framework_map

# ── Print framework report ─────────────────────────────────────
def print_framework_report(violations, summary, framework_map):
    print("\n" + "=" * 70)
    print("   LAYER 3 — COMPLIANCE FRAMEWORK MAPPING REPORT")
    print("=" * 70)
    print(f"   Generated at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Total Violations : {summary.get('total_violations', 0)}")
    print(f"   Overall Risk     : {summary.get('overall_risk', 'N/A')}")
    print("=" * 70)

    # ── Per-framework scores ───────────────────────────────────
    framework_scores = {}
    for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
        fw_violations = []
        for ctrl, viols in framework_map[fw].items():
            fw_violations.extend(viols)
        framework_scores[fw] = calc_score(fw_violations)

    # ── Per framework breakdown ────────────────────────────────
    for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
        controls    = framework_map[fw]
        score       = framework_scores[fw]
        total_viols = sum(len(v) for v in controls.values())

        status      = "CRITICAL" if score < 60 else "HIGH" if score < 75 else "MEDIUM" if score < 90 else "PASSING"
        status_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "PASSING": "🟢"}.get(status, "⚪")

        print(f"\n{status_icon} {fw}")
        print(f"   Score          : {score}/100")
        print(f"   Status         : {status}")
        print(f"   Violations     : {total_viols}")
        print(f"   Controls Hit   : {len(controls)}")
        print(f"   " + "-" * 50)

        if not controls:
            print(f"   ✅ No violations found for this framework")
        else:
            for control, viols in controls.items():
                print(f"\n   Control: {control}")
                for v in viols:
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.get("severity"), "⚪")
                    print(f"      {sev_icon} [{v.get('id')}] {v.get('title')}")
                    print(f"         Source : {v.get('source')}")
                    print(f"         User   : {v.get('user')}")
                    print(f"         Fix    : {v.get('remediation')}")

    # ── Summary table ──────────────────────────────────────────
    print("\n\n" + "=" * 70)
    print("   FRAMEWORK SCORE SUMMARY")
    print("=" * 70)
    print(f"   {'Framework':<12} {'Score':>8}   {'Status':<10}   {'Violations':>10}")
    print(f"   {'-'*12} {'-'*8}   {'-'*10}   {'-'*10}")

    for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
        score       = framework_scores[fw]
        total_viols = sum(len(v) for v in framework_map[fw].values())
        status      = "CRITICAL" if score < 60 else "HIGH" if score < 75 else "MEDIUM" if score < 90 else "PASSING"
        print(f"   {fw:<12} {score:>6}/100   {status:<10}   {total_viols:>10}")

    overall = sum(framework_scores.values()) // len(framework_scores)
    print(f"\n   Overall Compliance Score : {overall}/100")
    print("=" * 70)

    # ── Priority remediation list ──────────────────────────────
    print("\n\n   TOP PRIORITY FIXES (Critical first)")
    print("-" * 70)
    severity_order    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_violations = sorted(violations, key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))

    for i, v in enumerate(sorted_violations, 1):
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.get("severity"), "⚪")
        print(f"\n   {i}. {sev_icon} [{v.get('severity')}] {v.get('title')}")
        print(f"      Fix: {v.get('remediation')}")

    print("\n" + "=" * 70)
    print("   ✅ Framework mapping complete!")
    print("=" * 70 + "\n")

    # ── Save mapped report ─────────────────────────────────────
    output = {
        "generated_at":    datetime.now().isoformat(),
        "overall_score":   overall,
        "framework_scores": framework_scores,
        "framework_map":   framework_map,
        "priority_fixes":  [
            {
                "rank":        i + 1,
                "id":          v.get("id"),
                "severity":    v.get("severity"),
                "title":       v.get("title"),
                "remediation": v.get("remediation")
            }
            for i, v in enumerate(sorted_violations)
        ]
    }

    with open("framework_mapping_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("📄 Framework mapping report saved to: framework_mapping_report.json\n")

    return output

# ── Run ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🗺️  Running Layer 3 — Framework Mapper...")

    with open("violation_report.json", "r") as f:
        report = json.load(f)

    violations    = report.get("violations", [])
    summary       = report.get("summary", {})
    framework_map = build_framework_map(violations)

    print_framework_report(violations, summary, framework_map)
