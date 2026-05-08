"""

spacy_detector.py — NLP-Based Compliance Violation Detector (Layer A1)

────────────────────────────────────────────────────────────────────────

Uses spaCy PhraseMatcher, EntityRuler, and NER to detect compliance

violations from natural language fields in GitHub webhook payloads.
 
Handles:

  • SP001 — Privilege escalation / admin access   (PhraseMatcher + context)

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
 
Design decisions:

  • spaCy model is lazy-loaded on first call — import never crashes.

  • Single-word high-FP phrases (admin, root, sudo) require an action

    verb nearby to confirm intent before firing.

  • Matched phrase is captured and included in violation description.

  • Scans user-controlled text, PR body, and fetched file contents.

"""
 
from datetime import datetime

from typing import Optional
 
# ── Lazy globals — populated on first call to run_spacy_detector() ───

_nlp             = None

_matcher         = None

_rule_phrase_map: dict = {}
 
 
# ══════════════════════════════════════════════════════════════════════

#  RULE DEFINITIONS

# ══════════════════════════════════════════════════════════════════════
 
PHRASE_RULES = [

    {

        "rule_id":  "SP001",

        "title":    "Privilege escalation or admin role granted",

        "severity": "CRITICAL",

        "frameworks": {

            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",

            "SOC2":     "CC6.1 – Logical Access Controls",

            "HIPAA":    "164.312(a)(1) – Access Control",

            "GDPR":     None,

        },

        "remediation": (

            "Revoke elevated privileges immediately, audit role change history, "

            "enforce least-privilege policy and require approval for all role changes."

        ),

        "phrases": [

            "privilege escalation", "role granted", "elevated access",

            "admin role", "escalated privileges", "administrator access",

            "root access", "superadmin", "admin access granted",

            "privilege grant", "role escalation", "sudo access",

            "superuser access", "escalate privilege",

        ],

        "_context_phrases": ["admin", "root", "superuser", "sudo"],

        "_context_verbs":   ["grant", "granted", "assign", "assigned", "add", "added",

                             "escalat", "elevat", "promoted", "given", "enable", "enabled"],

    },

    {

        "rule_id":  "SP003",

        "title":    "PII or sensitive data accessed or exported",

        "severity": "HIGH",

        "frameworks": {

            "ISO27001": "A.18.1.4 – Privacy and Protection of PII",

            "SOC2":     "CC6.1 – Logical Access Controls",

            "HIPAA":    "164.312(b) – Audit Controls",

            "GDPR":     "Article 5 – Principles of Data Processing",

        },

        "remediation": (

            "Restrict PII field access to authorised roles, mask sensitive fields "

            "in logs, enable field-level encryption, and audit the access event."

        ),

        "phrases": [

            "PII", "personal data", "SSN", "social security number", "passport number",

            "credit card", "PHI", "patient data", "medical record", "medical records",

            "sensitive data", "personally identifiable", "health information",

            "protected health", "personal information", "private data",

            "confidential data", "GDPR data", "data subject",

        ],

    },

    {

        "rule_id":  "SP004",

        "title":    "MFA not enforced or authentication failure",

        "severity": "HIGH",

        "frameworks": {

            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",

            "SOC2":     "CC6.1 – Logical Access Controls",

            "HIPAA":    "164.312(a)(1) – Access Control",

            "GDPR":     None,

        },

        "remediation": (

            "Enable MFA for all privileged accounts, investigate repeated auth "

            "failures, block suspicious IPs, and alert the security team."

        ),

        "phrases": [

            "no MFA", "MFA disabled", "MFA not enabled", "MFA bypass",

            "failed login", "auth failure", "authentication failed",

            "brute force", "invalid credentials", "multiple failed attempts",

            "authentication error", "login failed", "password failure",

            "account locked", "too many attempts", "credential stuffing",

            "2FA disabled", "two factor disabled", "no MFA required",

        ],

    },

    {

        "rule_id":  "SP006",

        "title":    "Security scan skipped or change management bypassed",

        "severity": "HIGH",

        "frameworks": {

            "ISO27001": "A.14.2.4 – Secure Development Policy",

            "SOC2":     "CC8.1 – Change Management for Production",

            "HIPAA":    None,

            "GDPR":     None,

        },

        "remediation": (

            "Enforce mandatory security scans in CI/CD pipeline, review and "

            "revoke bypass permissions, and require re-approval for the change."

        ),

        "phrases": [

            "skip scan", "bypass scan", "scan disabled", "no security scan",

            "force push", "skip review", "override approval", "emergency change",

            "scan skipped", "review bypassed", "approval bypassed",

            "skipping scan", "--no-verify", "scan override", "bypass pipeline",

            "skip ci", "no-verify flag", "disable scan", "skipping security scan",

        ],

    },

    {

        "rule_id":  "SP009",

        "title":    "Excessive or wildcard permissions assigned",

        "severity": "MEDIUM",

        "frameworks": {

            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",

            "SOC2":     "CC6.1 – Logical Access Controls",

            "HIPAA":    "164.312(a)(1) – Access Control",

            "GDPR":     None,

        },

        "remediation": (

            "Apply least-privilege principle, replace wildcard permissions with "

            "scoped policies, and review IAM roles quarterly."

        ),

        "phrases": [

            "full access", "all permissions", "wildcard policy", "wildcard permission",

            "excessive permission", "over privileged", "unrestricted access",

            "overprivileged", "blanket access", "open permissions",

            "* permissions", "grant all", "allow *",

        ],

    },

    {

        "rule_id":  "SP010",

        "title":    "Unusual access time or geographic anomaly",

        "severity": "MEDIUM",

        "frameworks": {

            "ISO27001": "A.12.4.1 – Event Logging",

            "SOC2":     "CC6.6 – System Monitoring",

            "HIPAA":    "164.312(b) – Audit Controls",

            "GDPR":     "Article 5 – Principles of Data Processing",

        },

        "remediation": (

            "Investigate source IP, enable geo-blocking for high-risk regions, "

            "notify user, and enforce re-authentication."

        ),

        "phrases": [

            "unusual location", "suspicious location", "unusual time", "off hours",

            "anomalous access", "geo block", "unknown IP", "foreign IP",

            "VPN detected", "unexpected location", "suspicious IP",

            "outside business hours", "unusual activity", "geographic anomaly",

            "login from new location", "unrecognized device",

        ],

    },

    {

        "rule_id":  "SP012",

        "title":    "Compliance policy exception or bypass requested",

        "severity": "HIGH",

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

            "temporary bypass", "disable audit log", "bypass compliance",

            "exception requested", "waive requirement", "skip compliance",

            "audit log disabled", "logging disabled", "override approval needed",

        ],

    },

]
 
 
# ══════════════════════════════════════════════════════════════════════

#  CUSTOM ENTITY RULER PATTERNS

# ══════════════════════════════════════════════════════════════════════
 
ENTITY_RULER_PATTERNS = [

    {"label": "SECURITY_EVENT", "pattern": "privilege escalation"},

    {"label": "SECURITY_EVENT", "pattern": "brute force"},

    {"label": "SECURITY_EVENT", "pattern": "unauthorized access"},

    {"label": "SECURITY_EVENT", "pattern": "data breach"},

    {"label": "SECURITY_EVENT", "pattern": "credential stuffing"},

    {"label": "PII_ACCESS",     "pattern": "personal data"},

    {"label": "PII_ACCESS",     "pattern": "patient records"},

    {"label": "PII_ACCESS",     "pattern": "medical records"},

    {"label": "PII_ACCESS",     "pattern": "credit card"},

    {"label": "PII_ACCESS",     "pattern": "social security number"},

    {"label": "AUTH_FAILURE",   "pattern": "failed login"},

    {"label": "AUTH_FAILURE",   "pattern": "authentication failed"},

    {"label": "AUTH_FAILURE",   "pattern": "invalid credentials"},

    {"label": "AUTH_FAILURE",   "pattern": "brute force"},

    {"label": "POLICY_BYPASS",  "pattern": "bypass scan"},

    {"label": "POLICY_BYPASS",  "pattern": "skip review"},

    {"label": "POLICY_BYPASS",  "pattern": "override approval"},

    {"label": "POLICY_BYPASS",  "pattern": "compliance bypass"},

    {"label": "POLICY_BYPASS",  "pattern": "temporary bypass"},

    {"label": "POLICY_BYPASS",  "pattern": "policy exception"},

    {"label": "POLICY_BYPASS",  "pattern": "audit log disabled"},

    {"label": "POLICY_BYPASS",  "pattern": "skipping security scan"},

    {"label": "POLICY_BYPASS",  "pattern": "override approval needed"},

]
 
 
# ══════════════════════════════════════════════════════════════════════

#  LAZY MODEL INITIALISATION

# ══════════════════════════════════════════════════════════════════════
 
def _get_nlp():

    """Load spaCy model and build matcher on first call. Raises clearly if missing."""

    global _nlp, _matcher, _rule_phrase_map
 
    if _nlp is not None:

        return _nlp, _matcher, _rule_phrase_map
 
    try:

        import spacy

        from spacy.matcher import PhraseMatcher

    except ImportError:

        raise ImportError("spacy is not installed. Run: pip install spacy")
 
    try:

        nlp = spacy.load("en_core_web_sm")

    except OSError:

        raise OSError(

            "spaCy model 'en_core_web_sm' not found.\n"

            "Run: python3 -m spacy download en_core_web_sm"

        )
 
    ruler = nlp.add_pipe("entity_ruler", before="ner")

    ruler.add_patterns(ENTITY_RULER_PATTERNS)
 
    matcher         = PhraseMatcher(nlp.vocab, attr="LOWER")

    rule_phrase_map = {}
 
    for rule in PHRASE_RULES:

        for phrase in rule["phrases"]:

            key      = f"{rule['rule_id']}::{phrase}"

            patterns = [nlp.make_doc(phrase)]

            matcher.add(key, patterns)

            rule_phrase_map[key] = (rule, phrase)
 
    _nlp             = nlp

    _matcher         = matcher

    _rule_phrase_map = rule_phrase_map
 
    return _nlp, _matcher, _rule_phrase_map
 
 
# ══════════════════════════════════════════════════════════════════════

#  HELPERS

# ══════════════════════════════════════════════════════════════════════
 
def _extract_user(payload: dict) -> str:

    """Extract the acting user from a GitHub webhook payload."""

    if isinstance(payload.get("pull_request"), dict):

        login = payload["pull_request"].get("user", {}).get("login", "")

        if login:

            return login

    if isinstance(payload.get("sender"), dict):

        return payload["sender"].get("login", "Unknown")

    if isinstance(payload.get("pusher"), dict):

        return payload["pusher"].get("name", "Unknown")

    return "Unknown"
 
 
def _extract_timestamp(payload: dict) -> str:

    """Extract the best available timestamp from a GitHub webhook payload."""

    candidates = [

        payload.get("pull_request", {}).get("created_at") if isinstance(payload.get("pull_request"), dict) else None,

        payload.get("head_commit", {}).get("timestamp") if isinstance(payload.get("head_commit"), dict) else None,

        payload.get("created_at"),

        payload.get("timestamp"),

    ]

    for ts in candidates:

        if ts:

            return str(ts)

    return datetime.utcnow().isoformat()
 
 
def _flatten_field(value, max_depth: int = 6, _depth: int = 0) -> str:

    """Recursively stringify a value for NLP scanning, with depth cap."""

    if _depth > max_depth:

        return ""

    if isinstance(value, dict):

        return " ".join(_flatten_field(v, max_depth, _depth + 1) for v in value.values())

    if isinstance(value, list):

        return " ".join(_flatten_field(i, max_depth, _depth + 1) for i in value)

    return str(value)
 
 
def _get_user_text_fields(payload: dict) -> str:

    """

    Extract user-controlled text from a GitHub webhook payload for NLP scanning.
 
    Includes:

    - Standard webhook fields (commits, PR, comments)

    - PR title + body explicitly (GitHub nests these under pull_request.body,

      NOT at payload top level — without explicit extraction they're missed)

    - _scannable_text injected by github_fetcher.py (actual file contents)
 
    Excludes GitHub metadata fields (URLs, IDs, node_ids) that generate noise.

    """

    # Standard top-level fields

    top_level_fields = [

        "title", "body", "message", "description", "name",

        "commits", "head_commit", "comment", "review",

        "_scannable_text",   # ← actual file contents fetched from GitHub API

    ]

    parts = []

    for field in top_level_fields:

        value = payload.get(field)

        if value:

            parts.append(_flatten_field(value))
 
    # ── PR body is nested under pull_request.body — extract explicitly ──

    # GitHub sends pull_request events with the PR description at

    # payload["pull_request"]["body"]. Without this, bypass/MFA phrases

    # in PR descriptions (test 5) are never scanned by spaCy.

    pr = payload.get("pull_request", {})

    if isinstance(pr, dict):

        for pr_field in ["title", "body"]:

            val = pr.get(pr_field)

            if val and isinstance(val, str):

                parts.append(val)
 
    # ── Commit messages are nested under commits[].message ──────────────

    # _flatten_field on "commits" recurses into them, but we also extract

    # head_commit.message directly for push events to ensure it's caught.

    head_commit = payload.get("head_commit", {})

    if isinstance(head_commit, dict):

        msg = head_commit.get("message", "")

        if msg:

            parts.append(msg)
 
    return " ".join(parts)
 
 
def _check_context_phrase(text_lower: str, phrase: str, verbs: list[str],

                           window: int = 60) -> Optional[str]:

    """

    For high-FP single-word phrases (admin, root, sudo), confirm intent by

    checking for an action verb within `window` characters on either side.

    Returns the matched context string or None.

    """

    idx = text_lower.find(phrase)

    while idx != -1:

        start   = max(0, idx - window)

        end     = min(len(text_lower), idx + len(phrase) + window)

        context = text_lower[start:end]

        if any(verb in context for verb in verbs):

            return context[:120]

        idx = text_lower.find(phrase, idx + 1)

    return None
 
 
def _extract_ner_metadata(spacy_doc, payload: dict) -> tuple[str, str, list, list]:

    """

    Run NER on a spaCy doc and return:

      (user_fallback, timestamp_fallback, custom_entity_labels, location_texts)

    """

    user_fallback = ""

    ts_fallback   = ""

    custom_labels = []

    locations     = []
 
    for ent in spacy_doc.ents:

        if ent.label_ in ("PERSON", "ORG") and not user_fallback:

            user_fallback = ent.text

        elif ent.label_ in ("DATE", "TIME") and not ts_fallback:

            ts_fallback = ent.text

        elif ent.label_ == "GPE":

            locations.append(ent.text)

        elif ent.label_ in ("SECURITY_EVENT", "PII_ACCESS", "AUTH_FAILURE", "POLICY_BYPASS"):

            custom_labels.append(ent.label_)
 
    return user_fallback, ts_fallback, sorted(set(custom_labels)), locations[:3]
 
 
# ══════════════════════════════════════════════════════════════════════

#  MAIN DETECTOR

# ══════════════════════════════════════════════════════════════════════
 
def run_spacy_detector(data: dict) -> list[dict]:

    """

    Scan GitHub webhook payloads with spaCy PhraseMatcher + NER + EntityRuler.
 
    Args:

        data: dict of {repo_name: [list of payload dicts]}
 
    Returns:

        List of violation dicts.

    """

    nlp, matcher, rule_phrase_map = _get_nlp()
 
    violations   = []

    seen_combos  = set()

    violation_id = 1
 
    for repo_name, payloads in data.items():

        for payload in payloads:

            doc_id = (

                payload.get("after")

                or str(payload.get("pull_request", {}).get("number", ""))

                or payload.get("delivery", "unknown")

            )
 
            # Build scan text from user fields + PR body + file contents

            scan_text = _get_user_text_fields(payload)

            if not scan_text.strip():

                continue
 
            # Cap at 100k chars to avoid memory spikes on huge diff payloads

            spacy_doc  = nlp(scan_text[:100_000])

            text_lower = scan_text.lower()
 
            # ── PhraseMatcher ─────────────────────────────────────

            matches     = matcher(spacy_doc)

            fired_rules: dict[str, tuple] = {}
 
            for match_id, _start, _end in matches:

                key   = nlp.vocab.strings[match_id]

                entry = rule_phrase_map.get(key)

                if entry:

                    rule, phrase = entry

                    if rule["rule_id"] not in fired_rules:

                        fired_rules[rule["rule_id"]] = (rule, phrase)
 
            # ── Context check for high-FP single-word SP001 phrases ─

            sp001_rule = next((r for r in PHRASE_RULES if r["rule_id"] == "SP001"), None)

            if sp001_rule and "SP001" not in fired_rules:

                ctx_phrases = sp001_rule.get("_context_phrases", [])

                ctx_verbs   = sp001_rule.get("_context_verbs", [])

                for phrase in ctx_phrases:

                    ctx = _check_context_phrase(text_lower, phrase, ctx_verbs)

                    if ctx:

                        fired_rules["SP001"] = (sp001_rule, f"{phrase} [context: ...{ctx.strip()[:60]}...]")

                        break
 
            # ── NER for metadata enrichment ───────────────────────

            user_ner, ts_ner, custom_labels, locations = _extract_ner_metadata(spacy_doc, payload)
 
            user_info = _extract_user(payload) or user_ner or "Unknown"

            timestamp = _extract_timestamp(payload) or ts_ner or datetime.utcnow().isoformat()
 
            # ── Build one violation per unique rule fired ──────────

            for rule_id, (rule, matched_phrase) in fired_rules.items():

                combo_key = (rule_id, repo_name, str(doc_id))

                if combo_key in seen_combos:

                    continue

                seen_combos.add(combo_key)
 
                geo_note = f" | Locations: {', '.join(locations)}" if locations else ""

                ent_note = f" | Entities: {', '.join(custom_labels)}" if custom_labels else ""
 
                violations.append({

                    "id":            f"SP{violation_id:03d}",

                    "detection":     "SPACY",

                    "rule_id":       rule_id,

                    "source":        repo_name,

                    "severity":      rule["severity"],

                    "title":         rule["title"],

                    "description":   (

                        f"[{rule_id}] {rule['title']} in repo '{repo_name}'. "

                        f"Matched phrase: \"{matched_phrase}\".{ent_note}{geo_note}"

                    ),

                    "user_involved":  user_info,

                    "timestamp":      timestamp,

                    "frameworks":     rule["frameworks"],

                    "remediation":    rule["remediation"],

                    "matched_text":   matched_phrase,

                })

                violation_id += 1
 
    return violations
 
 
# ══════════════════════════════════════════════════════════════════════

#  STANDALONE ENTRY POINT

# ══════════════════════════════════════════════════════════════════════
 
if __name__ == "__main__":

    import os

    import json
 
    ROOT         = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

    WEBHOOK_FILE = os.path.join(ROOT, "webhook_data.json")
 
    if not os.path.exists(WEBHOOK_FILE):

        print(f"❌ No webhook_data.json found at {WEBHOOK_FILE}")

        raise SystemExit(1)
 
    with open(WEBHOOK_FILE) as f:

        raw = json.load(f)
 
    entries = raw if isinstance(raw, list) else [{"payload": raw}]

    latest  = entries[-1]

    payload = latest.get("payload", latest)

    repo    = payload.get("repository", {}).get("full_name", "GITHUB_WEBHOOK")

    data: dict[str, list] = {repo: [payload]}
 
    print("🧠 Running standalone spaCy detector (Layer A1)...\n")

    results = run_spacy_detector(data)

    print(f"✅ spaCy detector found {len(results)} violation(s):\n")

    for v in results:

        print(f"  [{v['id']}] {v['severity']:8s}  {v['title']}")

        print(f"           Matched : {v.get('matched_text', 'N/A')}")

        print(f"           User    : {v['user_involved']}")

        print()
 