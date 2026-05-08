"""
regex_detector.py — Structural-Pattern Compliance Detector (Layer A2)
──────────────────────────────────────────────────────────────────────
Scans GitHub webhook payloads using deterministic regex for STRUCTURAL
patterns that NLP cannot reliably handle: IP ranges, SQL commands,
protocol URLs, hardcoded secret formats, and sensitive file paths.
 
Detection categories:
  • RX002 — Public / open firewall / network exposure  (IP patterns)
  • RX005 — Bulk data export / DB dump commands        (SQL patterns)
  • RX007 — Unencrypted data transmission              (protocol URLs)
  • RX008 — Hardcoded secrets / tokens in code         (key formats)
  • RX011 — Critical compliance/security file modified (file paths)
"""
 
import re
from datetime import datetime
 
 
# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════
 
_SAFE_HTTP_DOMAINS = frozenset([
    "api.github.com", "github.com", "raw.githubusercontent.com",
    "avatars.githubusercontent.com", "codeload.github.com",
    "objects.githubusercontent.com",
])
 
_CRITICAL_FILE_RE = re.compile(
    r"(SECURITY\.md|\.github/CODEOWNERS|policy\.json|audit_config\.yml"
    r"|\.github/workflows/[\w\-]+security[\w\-]*\.yml"
    r"|compliance\.md|SOC2_report\.pdf"
    r"|\.env$|secrets\.yml|secrets\.yaml"
    r"|\.aws/credentials|id_rsa|id_ed25519)",
    re.IGNORECASE,
)
 
RULES = [
    {
        "rule_id":   "RX002",
        "title":     "Open / public network or firewall exposure",
        "severity":  "CRITICAL",
        "frameworks": {
            "ISO27001": "A.13.1.1 – Network Controls",
            "SOC2":     "CC6.6 – System Monitoring",
            "HIPAA":    "164.312(c)(1) – Transmission Security",
            "GDPR":     "Article 32 – Security of Processing",
        },
        "remediation": (
            "Restrict firewall rules to specific IP ranges, remove public ACLs, "
            "enable VPC flow logs, and audit security group rules immediately."
        ),
        "patterns": [
            re.compile(
                r"\b(0\.0\.0\.0/0|open[\s_-]?firewall|publicly[\s_-]?exposed"
                r"|inbound[\s_-]?all|allow[\s_-]?all|internet[\s_-]?facing"
                r"|security[\s_-]?group[\s_-]?open|unrestricted[\s_-]?ingress)\b",
                re.IGNORECASE,
            ),
        ],
    },
    {
        "rule_id":   "RX005",
        "title":     "Bulk data export or database dump detected",
        "severity":  "CRITICAL",
        "frameworks": {
            "ISO27001": "A.18.1.4 – Privacy and Protection of PII",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    "164.312(b) – Audit Controls",
            "GDPR":     "Article 5 – Principles of Data Processing",
        },
        "remediation": (
            "Restrict bulk export permissions, monitor CLI/API export commands, "
            "enforce encryption for exported data, and audit who triggered the export."
        ),
        "patterns": [
            re.compile(
                r"\b(SELECT\s+\*\s+FROM|dump[\s_-]?table|db[\s_-]?dump"
                r"|export[\s_-]?all|full[\s_-]?table[\s_-]?scan"
                r"|mysqldump|mongodump|pg_dump|pg_dumpall"
                r"|exfiltrat|data[\s_-]?exfil)\b",
                re.IGNORECASE,
            ),
        ],
    },
    {
        "rule_id":   "RX007",
        "title":     "Unencrypted data storage or transmission",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.13.1.1 – Network Controls",
            "SOC2":     "CC6.6 – System Monitoring",
            "HIPAA":    "164.312(c)(1) – Transmission Security",
            "GDPR":     "Article 32 – Security of Processing",
        },
        "remediation": (
            "Enforce TLS 1.2+ for all data in transit, enable encryption at rest "
            "(AES-256), and rotate keys regularly."
        ),
        "patterns": [
            re.compile(
                r"\b(no[\s_-]?TLS|encryption[\s_-]?disabled|no[\s_-]?ssl"
                r"|cleartext|insecure[\s_-]?connection|unencrypted"
                r"|plain[\s_-]?text[\s_-]?password|http_only)\b",
                re.IGNORECASE,
            ),
        ],
        "_url_pattern": re.compile(r"http://([^\s/\"']+)", re.IGNORECASE),
    },
    {
        "rule_id":   "RX008",
        "title":     "Hardcoded secret, token or credential detected",
        "severity":  "CRITICAL",
        "frameworks": {
            "ISO27001": "A.9.2.3 – Management of Privileged Access Rights",
            "SOC2":     "CC6.1 – Logical Access Controls",
            "HIPAA":    None,
            "GDPR":     None,
        },
        "remediation": (
            "Rotate the exposed credential immediately, remove it from git history "
            "using git-filter-repo, and migrate to a secrets manager "
            "(Vault / AWS Secrets Manager / GitHub Secrets)."
        ),
        "patterns": [
            re.compile(
                r"\b(api[_-]?key\s*[:=]\s*['\"]?\w{20,}"
                r"|password\s*[:=]\s*['\"][^\s'\"]{8,}['\"]"
                r"|secret\s*[:=]\s*['\"][^\s'\"]{8,}['\"]"
                r"|token\s*[:=]\s*['\"][^\s'\"]{16,}['\"])\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"(AKIA[0-9A-Z]{16}"           # AWS access key
                r"|ASIA[0-9A-Z]{16}"           # AWS STS key
                r"|ghp_[A-Za-z0-9]{36}"        # GitHub personal access token
                r"|ghs_[A-Za-z0-9]{36}"        # GitHub app token
                r"|sk-[A-Za-z0-9]{32,}"        # OpenAI key
                r"|xoxb-[0-9A-Za-z\-]{50,}"   # Slack bot token
                r"|xoxp-[0-9A-Za-z\-]{50,}"   # Slack user token
                r"|AIza[0-9A-Za-z\-_]{35})"    # Google API key
            ),
        ],
    },
    {
        "rule_id":   "RX011",
        "title":     "Modification of critical compliance or security file",
        "severity":  "HIGH",
        "frameworks": {
            "ISO27001": "A.12.1.2 – Change Management",
            "SOC2":     "CC8.1 – Change Management for Production",
            "HIPAA":    "164.312(b) – Audit Controls",
            "GDPR":     None,
        },
        "remediation": (
            "Review the file change immediately. Require secondary approval for "
            "all security/compliance file modifications and notify the compliance team."
        ),
        "patterns": [],
    },
]
 
RULES_BY_ID = {r["rule_id"]: r for r in RULES}
 
 
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
    """
    Recursively stringify a value for regex scanning.
    Caps recursion depth to avoid exploding on deeply nested payloads.
    """
    if _depth > max_depth:
        return ""
    if isinstance(value, dict):
        return " ".join(_flatten_field(v, max_depth, _depth + 1) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_field(i, max_depth, _depth + 1) for i in value)
    return str(value)
 
 
def _scan_fields(payload: dict, fields: list[str]) -> dict[str, str]:
    """
    Extract specific top-level fields from payload as flat strings.
    Returns {field_name: flat_text} for only the fields that exist.
    """
    result = {}
    for field in fields:
        value = payload.get(field)
        if value is not None:
            result[field] = _flatten_field(value)
    return result
 
 
def _find_match(patterns: list, text: str) -> str | None:
    """Return the first matched string, or None if no pattern matches."""
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(0)[:120]
    return None
 
 
def _check_unencrypted(payload: dict, rule: dict) -> str | None:
    """
    RX007-specific check. Returns matched text or None.
    Applies domain allowlist to http:// URLs to avoid flagging GitHub's own URLs.
    Also scans fetched file contents via _scannable_text.
    """
    scan_text = _flatten_field(payload)
    match = _find_match(rule["patterns"], scan_text)
    if match:
        return match
 
    url_pattern = rule.get("_url_pattern")
    if url_pattern:
        for m in url_pattern.finditer(scan_text):
            domain = m.group(1).split("/")[0].split(":")[0].lower()
            if domain not in _SAFE_HTTP_DOMAINS:
                return m.group(0)[:120]
    return None
 
 
def _check_modified_files(payload: dict) -> list[str]:
    """
    RX011: Extract all modified/added/removed file paths from push commit data.
    Returns list of matched critical filenames.
    """
    matched_files = []
    commits = payload.get("commits", [])
    if not commits and payload.get("head_commit"):
        commits = [payload["head_commit"]]
 
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        all_files = (
            commit.get("added", []) +
            commit.get("modified", []) +
            commit.get("removed", [])
        )
        for filepath in all_files:
            if _CRITICAL_FILE_RE.search(str(filepath)):
                matched_files.append(filepath)
 
    pr = payload.get("pull_request", {})
    if isinstance(pr, dict):
        pr_body = pr.get("body", "") or ""
        if _CRITICAL_FILE_RE.search(pr_body):
            matched_files.append("(mentioned in PR body)")
 
    return list(set(matched_files))
 
 
# ══════════════════════════════════════════════════════════════════════
#  MAIN DETECTOR
# ══════════════════════════════════════════════════════════════════════
 
def run_regex_detector(data: dict) -> list[dict]:
    """
    Scan GitHub webhook payloads with regex rules.
 
    Args:
        data: dict of {repo_name: [list of payload dicts]}
 
    Returns:
        List of violation dicts.
    """
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
            user_info = _extract_user(payload)
            timestamp = _extract_timestamp(payload)
 
            # ── High-signal text: user content + fetched file contents ─
            # _scannable_text is injected by github_fetcher.py and contains
            # the actual code of all changed files. This is the primary
            # source for secret/SQL/PII detection. Without it, detectors
            # only see commit metadata and miss all code-level violations.
            high_signal_fields = _scan_fields(payload, [
                "commits", "head_commit", "pull_request",
                "comment", "issue", "review",
                "_scannable_text",   # ← actual file contents from GitHub API
            ])
            high_signal_text = " ".join(high_signal_fields.values())
 
            # Full payload text for network/firewall rules — includes infra
            # configs and also picks up _scannable_text via recursive flatten
            full_text = _flatten_field(payload)
 
            for rule in RULES:
                rule_id   = rule["rule_id"]
                combo_key = (rule_id, repo_name, str(doc_id))
                if combo_key in seen_combos:
                    continue
 
                matched_text = None
 
                if rule_id == "RX002":
                    matched_text = _find_match(rule["patterns"], full_text)
 
                elif rule_id == "RX005":
                    matched_text = _find_match(rule["patterns"], high_signal_text)
 
                elif rule_id == "RX007":
                    matched_text = _check_unencrypted(payload, rule)
 
                elif rule_id == "RX008":
                    matched_text = _find_match(rule["patterns"], high_signal_text)
 
                elif rule_id == "RX011":
                    critical_files = _check_modified_files(payload)
                    if critical_files:
                        matched_text = ", ".join(critical_files[:5])
 
                if matched_text is None:
                    continue
 
                seen_combos.add(combo_key)
 
                violations.append({
                    "id":           f"RX{violation_id:03d}",
                    "detection":    "REGEX",
                    "rule_id":      rule_id,
                    "source":       repo_name,
                    "severity":     rule["severity"],
                    "title":        rule["title"],
                    "description":  (
                        f"[{rule_id}] {rule['title']} detected in repo '{repo_name}'. "
                        f"Matched: \"{matched_text}\""
                    ),
                    "user_involved": user_info,
                    "timestamp":    timestamp,
                    "frameworks":   rule["frameworks"],
                    "remediation":  rule["remediation"],
                    "matched_text": matched_text,
                })
                violation_id += 1
 
    return violations
 
 
# ══════════════════════════════════════════════════════════════════════
#  MERGE — combine spaCy + regex violations, deduplicating by rule_id
# ══════════════════════════════════════════════════════════════════════
 
def merge_violations(spacy_violations: list[dict], regex_violations: list[dict]) -> list[dict]:
    seen_rule_ids: dict[str, dict] = {}
 
    for v in spacy_violations + regex_violations:
        rid = v.get("rule_id", v.get("id", ""))
        if rid not in seen_rule_ids:
            seen_rule_ids[rid] = v
        else:
            existing = seen_rule_ids[rid]
            if v.get("matched_text") and not existing.get("matched_text"):
                seen_rule_ids[rid] = v
 
    merged    = list(seen_rule_ids.values())
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    merged.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 3))
 
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
 
    deductions = (
        counts["CRITICAL"] * 25 +
        counts["HIGH"]     * 15 +
        counts["MEDIUM"]   *  8 +
        counts["LOW"]      *  3
    )
    score = max(0, 100 - deductions)
    risk  = (
        "CRITICAL" if score < 40 else
        "HIGH"     if score < 60 else
        "MEDIUM"   if score < 80 else
        "LOW"
    )
 
    return {
        "total_violations": len(violations),
        "critical":         counts["CRITICAL"],
        "high":             counts["HIGH"],
        "medium":           counts["MEDIUM"],
        "low":              counts["LOW"],
        "compliance_score": score,
        "overall_risk":     risk,
        "llm_detections":   sum(1 for v in violations if v.get("detection") not in ("REGEX", "SPACY")),
        "spacy_detections": sum(1 for v in violations if v.get("detection") == "SPACY"),
        "regex_detections": sum(1 for v in violations if v.get("detection") == "REGEX"),
    }
 
 
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
 
    print("🔍 Running standalone regex detector...\n")
    results = run_regex_detector(data)
    print(f"✅ Regex detector found {len(results)} violation(s):\n")
    for v in results:
        print(f"  [{v['id']}] {v['severity']:8s}  {v['title']}")
        print(f"           Matched : {v.get('matched_text', 'N/A')}")
        print(f"           User    : {v['user_involved']}")
        print()