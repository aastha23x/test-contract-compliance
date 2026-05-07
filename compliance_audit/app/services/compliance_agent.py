import os
import json
from datetime import datetime

import requests
from dotenv import load_dotenv

# ── Hybrid layer: deterministic regex detector ────────────────
from app.services.detectors.spacy_detector import run_spacy_detector
from app.services.detectors.regex_detector import run_regex_detector, merge_violations, rebuild_summary

# ── Load environment variables ─────────────────────────────────
load_dotenv()

AZURE_API_KEY = os.getenv("AZURE_API_KEY")
AZURE_API_URL = os.getenv("AZURE_API_URL")
# Removed MongoDB connection since we are using GitHub Webhooks

# ── Serialize nested datetimes recursively ─────────────────────
def serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize(i) for i in obj]
    return obj

# ── Fetch webhook data ──────────────────────────────────────────
def fetch_all_data():
    if os.path.exists("webhook_data.json"):
        with open("webhook_data.json", "r") as f:
            data = json.load(f)
        repo_name = data.get("repository", {}).get("full_name", "GITHUB_WEBHOOK")
        return {repo_name: [data]}
    else:
        print("⚠️ No webhook_data.json found. Waiting for GitHub webhook data.")
        return {"GITHUB_WEBHOOK": []}

# ── Build prompt ───────────────────────────────────────────────
def build_prompt(data):
    return """
You are an expert AI Compliance and Security Audit Agent. Your task is to analyze the security and audit data logs provided below and detect ALL compliance violations. 

CRITICAL INSTRUCTION: You MUST extract REAL violations from the provided data. DO NOT hallucinate. 

For each REAL violation you discover, return ONLY this JSON format (this is just the structural template, you must fill it with the REAL data you extracted):
{
  "violations": [
    {
      "id": "<GENERATE_UNIQUE_ID>",
      "source": "<NAME_OF_THE_COLLECTION_WHERE_FOUND>",
      "severity": "<CRITICAL or HIGH or MEDIUM or LOW>",
      "title": "<A_DESCRIPTIVE_SHORT_TITLE>",
      "description": "<PROVIDE_AN_EXTREMELY_DETAILED_EXPLANATION: Write at least 2-3 paragraphs. Detail EXACTLY what happened in the GitHub event. Explain deeply WHY this violates compliance frameworks. Detail the specific security risks (e.g., data breach, lateral movement). Quote the exact problematic code, filename, or commit message from the payload.>",
      "user_involved": "<NAME_AND_EMAIL_IF_PRESENT>",
      "timestamp": "<EXACT_TIMESTAMP_FROM_LOG>",
      "frameworks": {
        "ISO27001": "<CONTROL_ID_AND_NAME or null>",
        "SOC2": "<CONTROL_ID_AND_NAME or null>",
        "HIPAA": "<CONTROL_ID_AND_NAME or null>",
        "GDPR": "<CONTROL_ID_AND_NAME or null>"
      },
      "remediation": "<EXACT_AND_DETAILED_STEPS_TO_FIX: Provide a step-by-step technical guide on how to fix this issue in the codebase or repository settings.>"
    }
  ],
  "summary": {
    "total_violations": <INTEGER_COUNT>,
    "critical": <INTEGER_COUNT>,
    "high": <INTEGER_COUNT>,
    "medium": <INTEGER_COUNT>,
    "low": <INTEGER_COUNT>,
    "compliance_score": "<SCORE_OUT_OF_100>",
    "overall_risk": "<CRITICAL or HIGH or MEDIUM or LOW>"
  }
}

Return ONLY the valid JSON. No markdown formatting, no explanations, no chat text.

DATA TO ANALYZE:
GITHUB WEBHOOK PAYLOAD:
""" + json.dumps(list(data.values())[0] if data else [], indent=2)

# ── Call Azure OpenAI API ──────────────────────────────────────
def run_compliance_agent(prompt):
    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_API_KEY
    }
    body = {
        "messages": [
            {
                "role": "system",
                "content": "You are an expert AI compliance and security audit agent. Always respond with valid JSON only."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "max_tokens": 8192  # FIX: increased from 4096 to prevent JSON truncation
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

    result = response.json()
    return result["choices"][0]["message"]["content"]

# ── Parse raw LLM response string → Python dict ───────────────
def parse_llm_response(result_json: str) -> dict | None:
    """Strip markdown fences and parse JSON. Returns None on failure."""
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


# ── Print violations ───────────────────────────────────────────
def print_results(violations: list, summary: dict):
    """Pretty-print the merged violation report to stdout."""
    print("\n" + "=" * 70)
    print("   HYBRID COMPLIANCE AGENT - VIOLATION REPORT")
    print("   (LLM + spaCy + Regex detections merged)")
    print("=" * 70)

    print(f"\nSUMMARY")
    print(f"   Total Violations : {summary.get('total_violations', 0)}")
    print(f"   Critical         : {summary.get('critical', 0)}")
    print(f"   High             : {summary.get('high', 0)}")
    print(f"   Medium           : {summary.get('medium', 0)}")
    print(f"   Low              : {summary.get('low', 0)}")
    print(f"   Compliance Score : {summary.get('compliance_score', 'N/A')} / 100")
    print(f"   Overall Risk     : {summary.get('overall_risk', 'N/A')}")
    print(f"   LLM Detections   : {summary.get('llm_detections', '?')}")
    print(f"   spaCy Detections : {summary.get('spacy_detections', '?')}")
    print(f"   Regex Detections : {summary.get('regex_detections', '?')}")

    print("\n" + "-" * 70)
    print(f"VIOLATIONS FOUND ({len(violations)})")
    print("-" * 70)

    for v in violations:
        tag = (
            " [SPACY] " if v.get("detection") == "SPACY"
            else " [REGEX] " if v.get("detection") == "REGEX"
            else " [LLM]  "
        )
        severity = v.get("severity", "")
        print(f"\n[{v.get('id')}]{tag} {v.get('title')}")
        print(f"   Severity   : {severity}")
        print(f"   Source     : {v.get('source')}")
        print(f"   User       : {v.get('user_involved', 'N/A')}")
        print(f"   Timestamp  : {v.get('timestamp', 'N/A')}")
        print(f"   Description: {v.get('description')}")

        frameworks = v.get("frameworks", {})
        active = {k: val for k, val in frameworks.items() if val}
        if active:
            print(f"   Frameworks :")
            for fw, control in active.items():
                print(f"      {fw}: {control}")

        print(f"   Remediation: {v.get('remediation')}")

    print("\n" + "=" * 70)
    print("   Compliance scan complete!")
    print("=" * 70 + "\n")

# ── Main ───────────────────────────────────────────────────────
if __name__ == "__main__":
    print("📦 Fetching data from GitHub Webhook payload...")
    data  = fetch_all_data()
    total = sum(len(v) for v in data.values())
    print(f"✅ Loaded {total} event(s) from webhook\n")

    # ── Layer A1: spaCy NLP detector (phrase match + NER) ──────────────
    print("🧠 Running spaCy Detector (Layer A1 — NLP phrases + NER)...")
    spacy_violations = run_spacy_detector(data)
    print(f"   spaCy found {len(spacy_violations)} violation(s)\n")

    # ── Layer A2: Regex detector (structural patterns only) ────────────
    print("🔎 Running Regex Detector (Layer A2 — structural patterns)...")
    regex_violations = run_regex_detector(data)
    print(f"   Regex found {len(regex_violations)} violation(s)\n")

    # ── Layer B: LLM analysis (contextual, AI-powered) ─────────────────
    print("🤖 Running LLM Compliance Agent (Layer B)...")
    prompt         = build_prompt(data)
    llm_raw        = run_compliance_agent(prompt)
    llm_parsed     = parse_llm_response(llm_raw) if llm_raw else None
    llm_violations = llm_parsed.get("violations", []) if llm_parsed else []
    print(f"   LLM found {len(llm_violations)} violation(s)\n")

    # ── Merge: combine spaCy + Regex, then deduplicate against LLM ────
    print("🔀 Merging LLM + spaCy + Regex results...")
    combined_deterministic = spacy_violations + regex_violations
    merged_violations = merge_violations(llm_violations, combined_deterministic)
    merged_summary    = rebuild_summary(merged_violations)
    print(
        f"   ✅ Merged total: {merged_summary['total_violations']} violations "
        f"({merged_summary['llm_detections']} LLM + "
        f"{merged_summary['spacy_detections']} spaCy + "
        f"{merged_summary['regex_detections']} Regex unique)\n"
    )


    # ── Print & save ───────────────────────────────────────────
    print_results(merged_violations, merged_summary)

    final_report = {
        "violations": merged_violations,
        "summary":    merged_summary,
    }
    with open("violation_report.json", "w") as f:
        json.dump(final_report, f, indent=2)
    print("📄 Full hybrid report saved to: violation_report.json")

