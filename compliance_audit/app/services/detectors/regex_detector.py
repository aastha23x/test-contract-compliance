"""
regex_detector.py — Structural-Pattern Compliance Detector (Layer A2)
──────────────────────────────────────────────────────────────────────
Scans raw MongoDB data using deterministic regex for STRUCTURAL patterns
that NLP cannot reliably handle (IP ranges, SQL commands, protocol URLs,
hardcoded secret formats).

Keyword/phrase-based rules (RX001, RX003, RX004, RX006, RX009, RX010)
have been moved to spacy_detector.py (Layer A1).

Detection categories kept here:
  • RX002 — Public / open firewall / network exposure  (IP patterns)
  • RX005 — Bulk data export / DB dump commands        (SQL patterns)
  • RX007 — Unencrypted data transmission              (protocol URLs)
  • RX008 — Hardcoded secrets / tokens in logs         (key formats)
  • RX011 — Critical Compliance File Modification      (File paths)
"""

import re
import json
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════
#  RULE DEFINITIONS
#  Each rule: {id, title, severity, frameworks, remediation, patterns}
#  patterns: list of (field_path_hint, compiled_regex)
# ══════════════════════════════════════════════════════════════════════

# ── Structural rules only (keyword rules moved to spacy_detector.py) ──
RULES = [
    {
        "rule_id":    "RX002",
        "title":      "Open / public network or firewall exposure",
        "severity":   "CRITICAL",
        "frameworks": {
            "ISO27001": "A.13.1.1 – Network Controls",
            "SOC2":     "CC6.6 – System Monitoring",
            "HIPAA":    "164.312(c)(1) – Transmission Security",
            "GDPR":     "Article 32 – Security of Processing",
        },
        "remediation": "Restrict firewall rules to specific IP ranges, remove public ACLs, enable VPC flow logs.",
        "patterns": [
            re.compile(r"\b(0\.0\.0\.0/0|open.?firewall|publicly.?exposed|inbound.?all|allow.?all|internet.?facing)\b", re.IGNORECASE),
        ],
    },
    {
        "rule_id":    "RX005",
        "title":      "Bulk data export detected",
        "severity":   "CRITICAL",
        "frameworks": {
            "ISO27001": "A.18.1.4 – Privacy and Protection of PII",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(b) – Audit Controls",
            "GDPR":     "Article 5 – Principles of Data Processing",
        },
        "remediation": "Restrict bulk export permissions, monitor CLI/API export commands, enforce encryption for exported data.",
        "patterns": [
            re.compile(r"\b(SELECT\s+\*|dump.?table|db.?dump|export.?all|full.?table.?scan|mysqldump|mongodump|pg_dump)\b", re.IGNORECASE),
        ],
    },
    {
        "rule_id":    "RX007",
        "title":      "Unencrypted data storage or transmission",
        "severity":   "HIGH",
        "frameworks": {
            "ISO27001": "A.13.1.1 – Network Controls",
            "SOC2":     "CC6.6 – System Monitoring",
            "HIPAA":    "164.312(c)(1) – Transmission Security",
            "GDPR":     "Article 32 – Security of Processing",
        },
        "remediation": "Enforce TLS 1.2+ for all data in transit, enable encryption at rest (AES-256), rotate keys regularly.",
        "patterns": [
            re.compile(r"(http://\S+|ftp://\S+|\bno.?TLS\b|\bencryption.?disabled\b|\bno.?ssl\b|\bcleartext\b|\binsecure.?connection\b|\bunencrypted\b|\bplain.?text\b)", re.IGNORECASE),
        ],
    },
    {
        "rule_id":    "RX008",
        "title":      "Hardcoded secret, token or password detected in data",
        "severity":   "CRITICAL",
        "frameworks": {
            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    None,
            "GDPR":     None,
        },
        "remediation": "Rotate exposed credentials immediately, migrate to secrets manager (Vault / AWS Secrets Manager), scan codebase for hardcoded secrets.",
        "patterns": [
            re.compile(r"\b(api[_-]?key\s*[:=]\s*['\"]?\w{16,}|password\s*[:=]\s*['\"]?\S{6,}|secret\s*[:=]\s*['\"]?\S{6,}|token\s*[:=]\s*['\"]?\S{16,})\b", re.IGNORECASE),
            re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32})"),  # AWS / GitHub / OpenAI key formats
        ],
    },
    {
        "rule_id":    "RX011",
        "title":      "Modification of Critical Compliance or Security File",
        "severity":   "HIGH",
        "frameworks": {
            "ISO27001": "A.12.1.2",
            "SOC2":     "CC8.1",
            "HIPAA":    "164.312(b)",
            "GDPR":     None,
        },
        "remediation": "Review changes to security policies or CI/CD configurations. Require secondary approval and notify the compliance team.",
        "patterns": [
            re.compile(r"\b(SECURITY\.md|\.github/CODEOWNERS|policy\.json|audit_config\.yml|\.github/workflows/security\.yml|compliance\.md|SOC2_report\.pdf)\b", re.IGNORECASE),
        ],
    },
]


# ══════════════════════════════════════════════════════════════════════
#  HELPER — flatten a nested dict/list into a single string for scanning
# ══════════════════════════════════════════════════════════════════════

def _flatten_doc(doc) -> str:
    """Recursively stringify all values in a document for regex scanning."""
    if isinstance(doc, dict):
        return " ".join(_flatten_doc(v) for v in doc.values())
    if isinstance(doc, list):
        return " ".join(_flatten_doc(i) for i in doc)
    return str(doc)


# ══════════════════════════════════════════════════════════════════════
#  MAIN DETECTOR
# ══════════════════════════════════════════════════════════════════════

def run_regex_detector(data: dict) -> list[dict]:
    """
    Scan all MongoDB collections with regex rules.

    Args:
        data: dict of {collection_name: [list of documents]}

    Returns:
        List of violation dicts in the same schema as LLM violations.
    """
    violations   = []
    seen_combos  = set()          # deduplicate (rule_id, doc_id)
    violation_id = 1

    for collection_name, docs in data.items():
        for doc in docs:
            doc_text = _flatten_doc(doc)
            doc_id   = doc.get("_id", "unknown")

            for rule in RULES:
                combo_key = (rule["rule_id"], str(doc_id))
                if combo_key in seen_combos:
                    continue

                matched = any(p.search(doc_text) for p in rule["patterns"])
                if not matched:
                    continue

                seen_combos.add(combo_key)

                # ── Extract useful metadata from the doc ──────────
                user_info = ""
                if "pull_request" in doc and isinstance(doc["pull_request"], dict):
                    pr_user = doc["pull_request"].get("user", {})
                    if isinstance(pr_user, dict) and "login" in pr_user:
                        user_info = f"{pr_user.get('login')} (ID: {pr_user.get('id', 'unknown')})"
                elif "sender" in doc and isinstance(doc["sender"], dict):
                    user_info = doc["sender"].get("login", "")
                
                if not user_info:
                    user_name  = doc.get("user", doc.get("username", doc.get("user_name", "")))
                    if isinstance(user_name, dict): user_name = user_name.get("login", "")
                    user_email = doc.get("email", doc.get("user_email", ""))
                    user_info  = f"{user_name} ({user_email})" if user_email else str(user_name) if user_name else "Unknown"

                timestamp  = (
                    doc.get("timestamp") or
                    doc.get("created_at") or
                    (doc.get("pull_request", {}).get("created_at") if isinstance(doc.get("pull_request"), dict) else None) or
                    doc.get("date") or
                    datetime.now().isoformat()
                )

                violations.append({
                    "id":           f"RX{violation_id:03d}",
                    "detection":    "REGEX",          # tag so we know origin
                    "rule_id":      rule["rule_id"],
                    "source":       collection_name.upper().replace("_", " "),
                    "severity":     rule["severity"],
                    "title":        rule["title"],
                    "description":  (
                        f"[REGEX RULE {rule['rule_id']}] Pattern match in '{collection_name}' "
                        f"document (id={doc_id}). Matched rule: {rule['title']}."
                    ),
                    "user_involved": user_info,
                    "timestamp":    str(timestamp),
                    "frameworks":   rule["frameworks"],
                    "remediation":  rule["remediation"],
                })
                violation_id += 1

    return violations


# ══════════════════════════════════════════════════════════════════════
#  MERGE  — combine LLM + regex violations, deduplicating by title
# ══════════════════════════════════════════════════════════════════════

def merge_violations(llm_violations: list[dict], regex_violations: list[dict]) -> list[dict]:
    """
    Merge LLM and regex results.
    Strategy:
      - LLM violations take precedence.
      - Regex violations are added only when their title does NOT already
        appear (case-insensitive fuzzy) in the LLM results.
      - All violations are re-indexed as V001, V002, … in severity order.
    """
    llm_titles = {v.get("title", "").lower() for v in llm_violations}

    # Filter regex: keep only findings NOT already caught by LLM
    unique_regex = []
    stopwords = {"or", "and", "in", "to", "a", "the", "of", "on", "for", "with", "is", "detected", "information"}
    llm_words_list = [set(t.split()) - stopwords for t in llm_titles]
    
    for rv in regex_violations:
        rx_title = rv.get("title", "").lower()
        rx_words  = set(rx_title.split()) - stopwords
        
        duplicate = False
        for lw in llm_words_list:
            overlap = rx_words & lw
            # Aggressive deduplication: if 2 meaningful words overlap, or a strong keyword overlaps
            if len(overlap) >= 2 or any(k in overlap for k in ["hardcoded", "password", "secret", "scan", "bypass", "admin", "privilege", "firewall"]):
                duplicate = True
                break
                
        if not duplicate:
            unique_regex.append(rv)

    merged = llm_violations + unique_regex

    # Re-sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    merged.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 3))

    # Re-index IDs
    for i, v in enumerate(merged, 1):
        v["id"] = f"V{i:03d}"

    return merged


# ══════════════════════════════════════════════════════════════════════
#  REBUILD SUMMARY after merge
# ══════════════════════════════════════════════════════════════════════

def rebuild_summary(violations: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        sev = v.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    total = len(violations)
    # Score: start 100, deduct per severity
    deductions = counts["CRITICAL"] * 25 + counts["HIGH"] * 15 + counts["MEDIUM"] * 8 + counts["LOW"] * 3
    score = max(0, 100 - deductions)

    if score < 40:
        risk = "CRITICAL"
    elif score < 60:
        risk = "HIGH"
    elif score < 80:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "total_violations":  total,
        "critical":          counts["CRITICAL"],
        "high":              counts["HIGH"],
        "medium":            counts["MEDIUM"],
        "low":               counts["LOW"],
        "compliance_score":  score,
        "overall_risk":      risk,
        "llm_detections":    sum(1 for v in violations if v.get("detection") not in ("REGEX", "SPACY")),
        "spacy_detections":  sum(1 for v in violations if v.get("detection") == "SPACY"),
        "regex_detections":  sum(1 for v in violations if v.get("detection") == "REGEX"),
    }


# ══════════════════════════════════════════════════════════════════════
#  STANDALONE ENTRY POINT (run directly for testing)
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os, sys
    from pymongo import MongoClient
    from dotenv import load_dotenv

    load_dotenv()
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB  = os.getenv("MONGO_DB",  "jira_audit_db")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db     = client[MONGO_DB]

    data = {}
    for col in ["access_logs", "audit_evidence", "cloud_audit", "db_activity", "deployments"]:
        docs = list(db[col].find({}))
        for d in docs:
            d["_id"] = str(d["_id"])
        data[col] = docs

    print("🔍 Running standalone regex detector...\n")
    results = run_regex_detector(data)
    print(f"✅ Regex detector found {len(results)} violations:\n")
    for v in results:
        print(f"  [{v['id']}] {v['severity']:8s}  {v['title']}")
        print(f"           Source: {v['source']}  |  User: {v['user_involved']}")
        print()

    client.close()
