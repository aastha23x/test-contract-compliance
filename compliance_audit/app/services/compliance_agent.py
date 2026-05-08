import os
import json
from datetime import datetime
 
import requests
from dotenv import load_dotenv
 
# ── Hybrid layer: deterministic detectors ────────────────────
from app.services.detectors.spacy_detector import run_spacy_detector
from app.services.detectors.regex_detector import run_regex_detector, merge_violations, rebuild_summary
 
# ── GitHub file content fetcher ───────────────────────────────
# This is what was missing — without it detectors only see commit
# metadata (author, filenames) not the actual code inside files.
from app.services.github_fetcher import enrich_payload_with_file_contents
 
# ── Load environment variables ────────────────────────────────
load_dotenv()
 
AZURE_API_KEY = os.getenv("AZURE_API_KEY")
AZURE_API_URL = os.getenv("AZURE_API_URL")
 
# ── Absolute path anchors ─────────────────────────────────────
ROOT          = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEBHOOK_DATA  = os.path.join(ROOT, "webhook_data.json")
VIOLATION_OUT = os.path.join(ROOT, "violation_report.json")
 
 
# ── Serialize nested datetimes recursively ────────────────────
def serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize(i) for i in obj]
    return obj
 
 
# ── Fetch webhook data + enrich with file contents ────────────
def fetch_all_data():
    """
    Reads webhook_data.json, calls GitHub API to fetch actual file
    contents for each changed file, and returns grouped data dict.
 
    WHY file fetching matters:
    GitHub webhooks only send commit metadata (author, SHA, filenames).
    The actual file contents — where secrets, SQL injections, PII live —
    are NOT in the webhook payload. Without fetching them, detectors
    scan empty commit messages and find nothing.
    """
    if not os.path.exists(WEBHOOK_DATA):
        print(f"⚠️  No webhook_data.json found at {WEBHOOK_DATA}. Waiting for GitHub webhook data.")
        return {"GITHUB_WEBHOOK": []}
 
    with open(WEBHOOK_DATA, "r") as f:
        raw = json.load(f)
 
    entries = raw if isinstance(raw, list) else [{"payload": raw}]
 
    grouped: dict[str, list] = {}
    for entry in entries:
        payload   = entry.get("payload", entry)
        repo_name = payload.get("repository", {}).get("full_name", "GITHUB_WEBHOOK")
 
        # ── Fetch actual file contents from GitHub API ────────
        # Enriches payload with _scannable_text and _fetched_file_contents
        payload = enrich_payload_with_file_contents(payload)
 
        grouped.setdefault(repo_name, []).append(payload)
 
    total = sum(len(v) for v in grouped.values())
    print(f"   Loaded {total} event(s) from {WEBHOOK_DATA}")
    return grouped
 
 
# ── Log what files are being scanned ─────────────────────────
def build_scan_data(data: dict) -> dict:
    """
    Logs which files will be scanned. The _scannable_text key injected
    by enrich_payload_with_file_contents is already in each payload —
    _flatten_doc in the detectors will pick it up automatically since
    it recursively stringifies all dict values.
    """
    for repo_name, payloads in data.items():
        for payload in payloads:
            files = payload.get("_fetched_file_contents", {})
            if files:
                print(f"   📂 Scanning {len(files)} file(s): {', '.join(list(files.keys())[:5])}")
    return data
 
 
# ── Build prompt ──────────────────────────────────────────────
def build_prompt(data: dict, base_violations: list) -> str:
    v_summary = []
    for v in base_violations:
        v_summary.append({
            "id":                v["id"],
            "title":             v["title"],
            "rule_id":           v["rule_id"],
            "source":            v["source"],
            "severity":          v["severity"],
            "user_involved":     v.get("user_involved"),
            "timestamp":         v.get("timestamp"),
            "basic_description": v["description"],
            "matched_text":      v.get("matched_text", ""),
        })
 
    all_payloads = []
    for payloads in data.values():
        for p in payloads:
            summary = {k: v for k, v in p.items()
                       if k not in ("_scannable_text", "_fetched_file_contents")}
            if p.get("_fetched_file_contents"):
                summary["_changed_files"] = list(p["_fetched_file_contents"].keys())
            all_payloads.append(summary)
 
    return """
You are an expert AI Compliance and Security Audit Agent.
 
Our deterministic rule engine (regex/spaCy) has already scanned the GitHub webhook data and identified the following compliance violations.
Your task is to ENRICH these existing violations with highly detailed, contextual explanations and precise remediation steps.
 
CRITICAL INSTRUCTION: Do NOT invent new violations. ONLY enrich the exact violations provided in the BASE VIOLATIONS list.
Keep the original "id", "title", "severity", "source", "user_involved", and "timestamp" exactly as they appear in the BASE VIOLATIONS list.
Your job is to generate a comprehensive "description" and "remediation" for each violation.
 
For each violation, return ONLY this JSON format:
{
  "violations": [
    {
      "id": "<USE_EXACT_ID_FROM_BASE>",
      "source": "<USE_EXACT_SOURCE_FROM_BASE>",
      "severity": "<USE_EXACT_SEVERITY_FROM_BASE>",
      "title": "<USE_EXACT_TITLE_FROM_BASE>",
      "user_involved": "<USE_EXACT_USER_FROM_BASE>",
      "timestamp": "<USE_EXACT_TIMESTAMP_FROM_BASE>",
      "description": "<PROVIDE_AN_EXTREMELY_DETAILED_EXPLANATION>",
      "remediation": "<EXACT_AND_DETAILED_STEPS_TO_FIX>"
    }
  ]
}
 
Return ONLY the valid JSON. No markdown formatting, no explanations, no chat text.
 
BASE VIOLATIONS:
""" + json.dumps(v_summary, indent=2) + """
 
GITHUB WEBHOOK PAYLOAD:
""" + json.dumps(all_payloads, indent=2)
 
 
# ── Call Azure OpenAI API ─────────────────────────────────────
def run_compliance_agent(prompt: str) -> str | None:
    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_API_KEY,
    }
    body = {
        "messages": [
            {"role": "system", "content": "You are an expert AI compliance and security audit agent. Always respond with valid JSON only."},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  8192,
    }
 
    print("🤖 Calling Azure OpenAI API...")
    try:
        response = requests.post(AZURE_API_URL, headers=headers, json=body, timeout=60)
    except requests.exceptions.Timeout:
        print("❌ Azure API request timed out.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Azure API request failed: {e}")
        return None
 
    if response.status_code != 200:
        print(f"❌ API Error {response.status_code}: {response.text}")
        return None
 
    return response.json()["choices"][0]["message"]["content"]
 
 
# ── Parse raw LLM response ────────────────────────────────────
def parse_llm_response(result_json: str) -> dict | None:
    try:
        result_json = result_json.strip()
        if result_json.startswith("```"):
            result_json = result_json.split("```")[1]
            if result_json.startswith("json"):
                result_json = result_json[4:]
        return json.loads(result_json)
    except json.JSONDecodeError as e:
        print(f"❌ Could not parse LLM response as JSON: {e}")
        print("Raw LLM response:")
        print(result_json)
        return None
 
 
# ── Build summary ─────────────────────────────────────────────
def build_summary(violations: list[dict], spacy_count: int, regex_count: int) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        sev = v.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
 
    deductions = counts["CRITICAL"]*25 + counts["HIGH"]*15 + counts["MEDIUM"]*8 + counts["LOW"]*3
    score = max(0, 100 - deductions)
    risk  = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW"
 
    return {
        "total_violations": len(violations),
        "critical":         counts["CRITICAL"],
        "high":             counts["HIGH"],
        "medium":           counts["MEDIUM"],
        "low":              counts["LOW"],
        "compliance_score": score,
        "overall_risk":     risk,
        "llm_detections":   0,
        "spacy_detections": spacy_count,
        "regex_detections": regex_count,
    }
 
 
# ── Print violations ──────────────────────────────────────────
def print_results(violations: list, summary: dict):
    print("\n" + "=" * 70)
    print("   HYBRID COMPLIANCE AGENT - VIOLATION REPORT")
    print("   (Rule Engine Detection + LLM Enrichment)")
    print("=" * 70)
    print(f"\nSUMMARY")
    print(f"   Total Violations : {summary.get('total_violations', 0)}")
    print(f"   Critical         : {summary.get('critical', 0)}")
    print(f"   High             : {summary.get('high', 0)}")
    print(f"   Medium           : {summary.get('medium', 0)}")
    print(f"   Low              : {summary.get('low', 0)}")
    print(f"   Compliance Score : {summary.get('compliance_score', 'N/A')} / 100")
    print(f"   Overall Risk     : {summary.get('overall_risk', 'N/A')}")
    print(f"   spaCy Detections : {summary.get('spacy_detections', '?')}")
    print(f"   Regex Detections : {summary.get('regex_detections', '?')}")
    print("\n" + "-" * 70)
    print(f"VIOLATIONS FOUND ({len(violations)})")
    print("-" * 70)
    for v in violations:
        tag = " [SPACY] " if v.get("detection") == "SPACY" else " [REGEX] " if v.get("detection") == "REGEX" else " [RULE]  "
        print(f"\n[{v.get('id')}]{tag} {v.get('title')}")
        print(f"   Severity   : {v.get('severity', '')}")
        print(f"   Source     : {v.get('source')}")
        print(f"   User       : {v.get('user_involved', 'N/A')}")
        print(f"   Matched    : {v.get('matched_text', 'N/A')}")
        print(f"   Description: {v.get('description')}")
        print(f"   Remediation: {v.get('remediation')}")
    print("\n" + "=" * 70)
    print("   Compliance scan complete!")
    print("=" * 70 + "\n")
 
 
# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("📦 Fetching data from GitHub Webhook payload...")
    data  = fetch_all_data()
    total = sum(len(v) for v in data.values())
    print(f"✅ Loaded {total} event(s) from webhook\n")
 
    # Log which files will be scanned
    scan_data = build_scan_data(data)
 
    # ── Layer A1: spaCy NLP detector ──────────────────────────
    print("🧠 Running spaCy Detector (Layer A1 — NLP phrases + NER)...")
    spacy_violations = run_spacy_detector(scan_data)
    print(f"   spaCy found {len(spacy_violations)} violation(s)\n")
 
    # ── Layer A2: Regex detector ──────────────────────────────
    print("🔎 Running Regex Detector (Layer A2 — structural patterns)...")
    regex_violations = run_regex_detector(scan_data)
    print(f"   Regex found {len(regex_violations)} violation(s)\n")
 
    base_violations = spacy_violations + regex_violations
 
    if not base_violations:
        print("✅ No violations found by rule engines. Skipping LLM enrichment.\n")
        final_violations = []
    else:
        # ── Layer B: LLM Context Enrichment ───────────────────
        print(f"🤖 Running LLM Enrichment on {len(base_violations)} violation(s)...")
        prompt     = build_prompt(data, base_violations)
        llm_raw    = run_compliance_agent(prompt)
        llm_parsed = parse_llm_response(llm_raw) if llm_raw else None
 
        if llm_parsed and "violations" in llm_parsed:
            enriched_map = {v["id"]: v for v in llm_parsed["violations"]}
            for v in base_violations:
                if v["id"] in enriched_map:
                    ev = enriched_map[v["id"]]
                    v["description"] = ev.get("description", v["description"])
                    v["remediation"] = ev.get("remediation", v.get("remediation", ""))
 
        final_violations = base_violations
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        final_violations.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 3))
        for i, v in enumerate(final_violations, 1):
            v["id"] = f"V{i:03d}"
 
    final_summary = build_summary(final_violations, len(spacy_violations), len(regex_violations))
 
    print_results(final_violations, final_summary)
 
    final_report = {"violations": final_violations, "summary": final_summary}
    with open(VIOLATION_OUT, "w") as f:
        json.dump(serialize(final_report), f, indent=2)
    print(f"📄 Full hybrid report saved to: {VIOLATION_OUT}")