"""
spacy_detector.py — NLP-Based Compliance Violation Detector (Layer A1)
────────────────────────────────────────────────────────────────────────
Uses spaCy PhraseMatcher, EntityRuler, and NER to detect compliance
violations from natural language fields in MongoDB documents.

Handles:
  • SP001 — Privilege escalation / admin access   (PhraseMatcher)
  • SP003 — PII / sensitive data access           (PhraseMatcher + EntityRuler)
  • SP004 — MFA failures / auth anomalies         (PhraseMatcher)
  • SP006 — Scan bypass / change mgmt skipped     (PhraseMatcher)
  • SP009 — Wildcard / excessive permissions      (PhraseMatcher)
  • SP010 — Geo / time anomalies                  (PhraseMatcher + NER)
  • SP012 — Compliance policy bypass requested    (PhraseMatcher)

NER extraction (en_core_web_sm):
  • PERSON / ORG  → enriches user_involved field
  • DATE / TIME   → enriches timestamp field
  • GPE           → geographic context in descriptions
"""

import spacy
from spacy.matcher import PhraseMatcher
from datetime import datetime


# ── Load spaCy model ──────────────────────────────────────────────────
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    raise OSError(
        "spaCy model 'en_core_web_sm' not found.\n"
        "Run: python3 -m spacy download en_core_web_sm"
    )


# ── Rule definitions (keyword/phrase-based rules only) ─────────────────
PHRASE_RULES = [
    {
        "rule_id":   "SP001",
        "title":     "Privilege escalation or admin role granted",
        "severity":  "CRITICAL",
        "frameworks": {
            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(a)(1) – Access Control",
            "GDPR":     None,
        },
        "remediation": (
            "Revoke elevated privileges immediately, audit role change history, "
            "enforce least-privilege policy."
        ),
        "phrases": [
            "admin", "root", "superuser", "sudo", "privilege escalation",
            "role granted", "elevated access", "admin role", "escalated privileges",
            "administrator access", "root access", "superadmin", "admin access",
            "privilege grant", "role escalation",
        ],
    },
    {
        "rule_id":   "SP003",
        "title":     "PII or sensitive data accessed or exported",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.18.1.4 – Privacy and Protection of PII",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(b) – Audit Controls",
            "GDPR":     "Article 5 – Principles of Data Processing",
        },
        "remediation": (
            "Restrict PII field access to authorised roles, mask sensitive fields "
            "in logs, enable field-level encryption."
        ),
        "phrases": [
            "PII", "personal data", "SSN", "social security", "passport",
            "credit card", "PHI", "patient data", "medical record",
            "sensitive data", "GDPR data", "personally identifiable",
            "health information", "protected health", "personal information",
            "private data", "confidential data",
        ],
    },
    {
        "rule_id":   "SP004",
        "title":     "MFA not enforced or authentication failure",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(a)(1) – Access Control",
            "GDPR":     None,
        },
        "remediation": (
            "Enable MFA for all privileged accounts, investigate repeated auth "
            "failures, block suspicious IPs."
        ),
        "phrases": [
            "no MFA", "MFA disabled", "MFA not enabled", "failed login",
            "auth failure", "authentication failed", "login attempt",
            "brute force", "invalid credentials", "multiple failed",
            "authentication error", "login failed", "password failure",
            "account locked", "too many attempts",
        ],
    },
    {
        "rule_id":   "SP006",
        "title":     "Security scan skipped or change management bypassed",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.14.2.4 – Secure Development Policy",
            "SOC2":     "CC8.1 – Change Management for Production",
            "HIPAA":    None,
            "GDPR":     None,
        },
        "remediation": (
            "Enforce mandatory security scans in CI/CD pipeline, review and "
            "revoke bypass permissions."
        ),
        "phrases": [
            "skip scan", "bypass scan", "scan disabled", "no security scan",
            "force push", "skip review", "override approval", "emergency change",
            "scan skipped", "review bypassed", "approval bypassed",
            "skipping scan", "no-verify", "scan override",
        ],
    },
    {
        "rule_id":   "SP009",
        "title":     "Excessive or wildcard permissions assigned",
        "severity":  "MEDIUM",
        "frameworks": {
            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(a)(1) – Access Control",
            "GDPR":     None,
        },
        "remediation": (
            "Apply least-privilege principle, replace wildcard permissions with "
            "scoped policies, review IAM roles quarterly."
        ),
        "phrases": [
            "full access", "all permissions", "wildcard policy",
            "excessive permission", "over privileged", "unrestricted access",
            "overprivileged", "admin permissions", "root permissions",
            "blanket access", "open permissions",
        ],
    },
    {
        "rule_id":   "SP010",
        "title":     "Unusual access time or geographic anomaly",
        "severity":  "MEDIUM",
        "frameworks": {
            "ISO27001": "A.12.4.1 – Event Logging",
            "SOC2":     "CC6.6 – System Monitoring",
            "HIPAA":    "164.312(b) – Audit Controls",
            "GDPR":     "Article 5 – Principles of Data Processing",
        },
        "remediation": (
            "Investigate source IP, enable geo-blocking for high-risk regions, "
            "notify user and enforce re-authentication."
        ),
        "phrases": [
            "unusual location", "suspicious location", "unusual time", "off hours",
            "anomalous access", "geo block", "unknown IP", "foreign IP",
            "VPN detected", "unexpected location", "suspicious IP",
            "outside business hours", "unusual activity", "geographic anomaly",
        ],
    },
    {
        "rule_id":   "SP012",
        "title":     "Compliance Policy Exception or Bypass Requested",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.18.1.4 – Privacy and Protection of PII",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    None,
            "GDPR":     None,
        },
        "remediation": (
            "Verify the legitimacy of the exception request. Ensure temporary bypasses "
            "are properly documented, time-bound, and approved by the security team."
        ),
        "phrases": [
            "policy exception", "compliance bypass", "override security", "ignore policy",
            "temporary bypass", "disable audit log", "bypass compliance", "exception requested"
        ],
    },
]


# ── Custom EntityRuler patterns (compliance-specific entity types) ─────
ENTITY_RULER_PATTERNS = [
    {"label": "SECURITY_EVENT", "pattern": "privilege escalation"},
    {"label": "SECURITY_EVENT", "pattern": "brute force"},
    {"label": "SECURITY_EVENT", "pattern": "unauthorized access"},
    {"label": "SECURITY_EVENT", "pattern": "data breach"},
    {"label": "PII_ACCESS",     "pattern": "personal data"},
    {"label": "PII_ACCESS",     "pattern": "patient records"},
    {"label": "PII_ACCESS",     "pattern": "medical records"},
    {"label": "PII_ACCESS",     "pattern": "credit card"},
    {"label": "AUTH_FAILURE",   "pattern": "failed login"},
    {"label": "AUTH_FAILURE",   "pattern": "authentication failed"},
    {"label": "AUTH_FAILURE",   "pattern": "invalid credentials"},
    {"label": "POLICY_BYPASS",  "pattern": "bypass scan"},
    {"label": "POLICY_BYPASS",  "pattern": "skip review"},
    {"label": "POLICY_BYPASS",  "pattern": "override approval"},
    {"label": "POLICY_BYPASS",  "pattern": "compliance bypass"},
    {"label": "POLICY_BYPASS",  "pattern": "temporary bypass"},
    {"label": "POLICY_BYPASS",  "pattern": "policy exception"},
]

# Add EntityRuler before the default NER so custom entities take precedence
ruler = nlp.add_pipe("entity_ruler", before="ner")
ruler.add_patterns(ENTITY_RULER_PATTERNS)


# ── Build PhraseMatcher (case-insensitive via LOWER attr) ─────────────
matcher       = PhraseMatcher(nlp.vocab, attr="LOWER")
rule_phrase_map = {}  # match_key → rule dict

for rule in PHRASE_RULES:
    for phrase in rule["phrases"]:
        key      = f"{rule['rule_id']}::{phrase}"
        patterns = [nlp.make_doc(phrase)]
        matcher.add(key, patterns)
        rule_phrase_map[key] = rule


# ── Helper: flatten nested dict/list → single string ─────────────────
def _flatten_doc(doc) -> str:
    """Recursively stringify all values for NLP scanning."""
    if isinstance(doc, dict):
        return " ".join(_flatten_doc(v) for v in doc.values())
    if isinstance(doc, list):
        return " ".join(_flatten_doc(i) for i in doc)
    return str(doc)


# ── Helper: extract user + timestamp using direct fields + NER ────────
def _extract_metadata(doc_obj: dict, spacy_doc) -> tuple[str, str]:
    """
    Extract user_involved and timestamp.
    Tries direct field lookup first; falls back to NER entities.
    """
    user_info = ""
    
    # GitHub specific fields
    if "pull_request" in doc_obj and isinstance(doc_obj["pull_request"], dict):
        pr_user = doc_obj["pull_request"].get("user", {})
        if isinstance(pr_user, dict) and "login" in pr_user:
            user_info = f"{pr_user.get('login')} (ID: {pr_user.get('id', 'unknown')})"
    elif "sender" in doc_obj and isinstance(doc_obj["sender"], dict):
        user_info = doc_obj["sender"].get("login", "")

    # Legacy fields
    if not user_info:
        user_name  = doc_obj.get("user", doc_obj.get("username", doc_obj.get("user_name", "")))
        if isinstance(user_name, dict): user_name = user_name.get("login", "")
        user_email = doc_obj.get("email", doc_obj.get("user_email", ""))
        user_info  = f"{user_name} ({user_email})" if user_email else str(user_name) if user_name else ""

    timestamp = (
        doc_obj.get("timestamp") or
        doc_obj.get("created_at") or
        (doc_obj.get("pull_request", {}).get("created_at") if isinstance(doc_obj.get("pull_request"), dict) else None) or
        doc_obj.get("date") or ""
    )

    # NER fallback — PERSON/ORG for user, DATE/TIME for timestamp
    if not user_info:
        persons = [ent.text for ent in spacy_doc.ents if ent.label_ in ("PERSON", "ORG")]
        if persons:
            user_info = persons[0]

    if not timestamp:
        dates = [ent.text for ent in spacy_doc.ents if ent.label_ in ("DATE", "TIME")]
        if dates:
            timestamp = dates[0]

    user_info = user_info or "Unknown"
    timestamp = str(timestamp) if timestamp else datetime.now().isoformat()
    return user_info, timestamp


# ── Main detector ─────────────────────────────────────────────────────
def run_spacy_detector(data: dict) -> list[dict]:
    """
    Scan all MongoDB collections with spaCy PhraseMatcher + NER + EntityRuler.

    Args:
        data: dict of {collection_name: [list of documents]}

    Returns:
        List of violation dicts in the same schema used by LLM and regex layers.
    """
    violations   = []
    seen_combos  = set()   # deduplicate (rule_id, doc_id)
    violation_id = 1

    for collection_name, docs in data.items():
        for doc in docs:
            doc_text = _flatten_doc(doc)
            doc_id   = doc.get("_id", "unknown")

            # Run full spaCy pipeline (cap at 100k chars to avoid memory spikes)
            spacy_doc = nlp(doc_text[:100_000])

            # PhraseMatcher — collect unique rules fired in this document
            matches     = matcher(spacy_doc)
            fired_rules = {}  # rule_id → rule (one entry per rule per doc)

            for match_id, _start, _end in matches:
                key  = nlp.vocab.strings[match_id]
                rule = rule_phrase_map.get(key)
                if rule:
                    fired_rules[rule["rule_id"]] = rule

            # Build one violation per unique rule fired
            for rule_id, rule in fired_rules.items():
                combo_key = (rule_id, str(doc_id))
                if combo_key in seen_combos:
                    continue
                seen_combos.add(combo_key)

                user_info, timestamp = _extract_metadata(doc, spacy_doc)

                # Collect custom entity types found in this doc
                custom_entities = sorted({
                    ent.label_ for ent in spacy_doc.ents
                    if ent.label_ in ("SECURITY_EVENT", "PII_ACCESS", "AUTH_FAILURE", "POLICY_BYPASS")
                })

                # Geographic context from NER
                locations = [ent.text for ent in spacy_doc.ents if ent.label_ == "GPE"]
                geo_note  = f" | Location context: {', '.join(locations[:3])}" if locations else ""
                ent_note  = f" | Entities: {', '.join(custom_entities)}" if custom_entities else ""

                violations.append({
                    "id":           f"SP{violation_id:03d}",
                    "detection":    "SPACY",
                    "rule_id":      rule_id,
                    "source":       collection_name.upper().replace("_", " "),
                    "severity":     rule["severity"],
                    "title":        rule["title"],
                    "description":  (
                        f"[SPACY {rule_id}] NLP phrase match in '{collection_name}' "
                        f"document (id={doc_id}). Rule: {rule['title']}.{ent_note}{geo_note}"
                    ),
                    "user_involved": user_info,
                    "timestamp":    timestamp,
                    "frameworks":   rule["frameworks"],
                    "remediation":  rule["remediation"],
                })
                violation_id += 1

    return violations


# ── Standalone entry point (run directly for testing) ─────────────────
if __name__ == "__main__":
    import os
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

    print("🧠 Running standalone spaCy detector (Layer A1)...\n")
    results = run_spacy_detector(data)
    print(f"✅ spaCy detector found {len(results)} violations:\n")
    for v in results:
        tag = "[SPACY]"
        print(f"  [{v['id']}] {tag} {v['severity']:8s}  {v['title']}")
        print(f"           Source: {v['source']}  |  User: {v['user_involved']}")
        print()

    client.close()
