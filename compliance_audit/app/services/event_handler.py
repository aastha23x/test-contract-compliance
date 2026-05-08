"""
event_handler.py
━━━━━━━━━━━━━━━━
Routes GitHub webhook events to the correct compliance checks.
Orchestrates the full pipeline: detect → map → create ticket → log.

Fixes applied:
  - Replaced broken RegexDetector().detect() / SpacyDetector().detect() class
    calls (those classes don't exist) with the correct run_regex_detector() and
    run_spacy_detector() function imports.
  - handle_pull_request_event now scans the full PR payload (title, body,
    comments) through both detectors — previously it never called them at all,
    causing PR comment violations (e.g. "No MFA", "override approval",
    "emergency change") to be silently missed.
  - handle_push_event now passes the full payload to detectors instead of only
    individual commit message strings, so regex rules that inspect PR / commit
    structure also fire correctly.
  - Added PR comment scanning in handle_pull_request_event via the
    `comment` field on issue_comment-style payloads and the PR body.
"""

import logging
from datetime import datetime
from pymongo import MongoClient

from app.services.detectors.regex_detector import run_regex_detector
from app.services.detectors.spacy_detector import run_spacy_detector
from app.services.framework_mapper import run_framework_mapper
from app.services.audit_logger import log_audit_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── MongoDB ────────────────────────────────────────────────────
mongo_client = MongoClient("mongodb://localhost:27017/")
db           = mongo_client["jira_audit_db"]


# ── Helper: run both detectors on a payload ────────────────────
def _run_detectors(payload: dict) -> list:
    """
    Run regex + spaCy detectors on a single payload.
    Both functions expect {repo_name: [payload_list]}.
    """
    repo_name = payload.get("repository", {}).get("full_name", "UNKNOWN_REPO")
    scan_data = {repo_name: [payload]}

    regex_violations = run_regex_detector(scan_data)
    spacy_violations = run_spacy_detector(scan_data)

    return regex_violations + spacy_violations


# ── Main entry point ───────────────────────────────────────────
async def handle_github_event(event_type: str, delivery_id: str, payload: dict) -> dict:
    """
    Main event handler — called by worker for every GitHub webhook event.
    Routes to the right compliance checks based on event type.
    """
    logger.info(f"[EventHandler] Handling: {event_type}")
    start_time = datetime.utcnow()

    # Store raw event in MongoDB
    db["github_events"].insert_one({
        "delivery_id": delivery_id,
        "event_type":  event_type,
        "received_at": start_time.isoformat(),
        "payload":     payload
    })

    # Route to correct handler
    violations = []

    if event_type == "push":
        violations = await handle_push_event(payload)

    elif event_type == "pull_request":
        violations = await handle_pull_request_event(payload)

    elif event_type == "pull_request_review":
        violations = await handle_pr_review_event(payload)

    elif event_type == "pull_request_review_comment":
        violations = await handle_pr_review_comment_event(payload)

    elif event_type == "issue_comment":
        violations = await handle_issue_comment_event(payload)

    elif event_type == "member":
        violations = await handle_member_event(payload)

    elif event_type == "repository":
        violations = await handle_repository_event(payload)

    elif event_type == "issues":
        violations = await handle_issues_event(payload)

    else:
        logger.info(f"[EventHandler] No compliance handler for event: {event_type}")

    # Process violations if any found
    jira_tickets = []
    if violations:
        # Map to frameworks
        mapped_violations = run_framework_mapper(violations)

        # Save to MongoDB
        for v in mapped_violations:
            db["violations"].insert_one({**v, "status": "OPEN"})

        # Create Jira tickets (import here to avoid circular imports if jira_creator
        # is not yet wired up — swap to top-level import once it exists)
        try:
            from app.services.jira_creator import create_jira_tickets
            jira_tickets = create_jira_tickets(mapped_violations)
        except ImportError:
            logger.warning("[EventHandler] jira_creator not available — skipping ticket creation")

        logger.info(
            f"[EventHandler] {len(violations)} violation(s) found, "
            f"{len(jira_tickets)} ticket(s) created"
        )

    # Log audit event
    duration = (datetime.utcnow() - start_time).total_seconds()
    await log_audit_event(event_type, delivery_id, len(violations), jira_tickets, duration)

    return {
        "event_type":       event_type,
        "delivery_id":      delivery_id,
        "violations_found": len(violations),
        "jira_tickets":     jira_tickets,
        "duration_seconds": duration,
    }


# ══════════════════════════════════════════════════════════════════════
#  EVENT HANDLERS
# ══════════════════════════════════════════════════════════════════════

async def handle_push_event(payload: dict) -> list:
    """
    Check push events:
      • Direct push to main/master  → CRITICAL structural violation
      • After-hours push            → MEDIUM structural violation
      • Full payload scan           → regex + spaCy on commit messages,
                                      diff text, and any other user fields
    """
    logger.info("[EventHandler] Checking push event")
    violations = []

    ref     = payload.get("ref", "")
    pusher  = payload.get("pusher", {}).get("name", "unknown")
    commits = payload.get("commits", [])
    repo    = payload.get("repository", {}).get("full_name", "unknown")

    # Rule 1 — direct push to main
    if ref in ["refs/heads/main", "refs/heads/master"]:
        violations.append({
            "id":            f"V-PUSH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":        "GITHUB_PUSH",
            "event_type":    "push",
            "severity":      "CRITICAL",
            "title":         "Direct push to main branch — bypassed PR process",
            "description":   (
                f"{pusher} pushed {len(commits)} commit(s) directly to "
                f"{ref} in {repo}"
            ),
            "user_involved": pusher,
            "timestamp":     datetime.utcnow().isoformat(),
            "remediation":   "Enable branch protection. Require PRs for all changes to main.",
        })

    # Rule 2 — after-hours push
    hour = datetime.utcnow().hour
    if hour < 8 or hour > 22:
        violations.append({
            "id":            f"V-HOURS-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":        "GITHUB_PUSH",
            "event_type":    "push",
            "severity":      "MEDIUM",
            "title":         "Code pushed outside business hours",
            "description":   (
                f"{pusher} pushed to {repo} at "
                f"{datetime.utcnow().strftime('%H:%M')} UTC"
            ),
            "user_involved": pusher,
            "timestamp":     datetime.utcnow().isoformat(),
            "remediation":   "Investigate the push. Verify it was not a compromised account.",
        })

    # FIX: pass the full payload to detectors (not individual commit message
    # strings). The detector functions expect {repo: [payload]} and scan all
    # user-controlled fields — commit messages, PR body, comments, etc.
    detector_violations = _run_detectors(payload)
    violations.extend(detector_violations)

    if detector_violations:
        logger.info(
            f"[EventHandler] Push scan found {len(detector_violations)} "
            f"NLP/regex violation(s)"
        )

    return violations


async def handle_pull_request_event(payload: dict) -> list:
    """
    Check PR events:
      • PR merged without review    → HIGH structural violation
      • Full payload NLP/regex scan → catches compliance language in PR title,
                                      body, and inline comments (e.g.
                                      "No MFA", "override approval",
                                      "skipping security scan")

    BUG FIX: Previously this handler never called the detectors, so any
    compliance-relevant language in PR comments was silently missed.
    """
    logger.info("[EventHandler] Checking pull request event")
    violations = []

    action  = payload.get("action", "")
    pr      = payload.get("pull_request", {})
    user    = pr.get("user", {}).get("login", "unknown")
    merged  = pr.get("merged", False)
    base    = pr.get("base", {}).get("ref", "")
    reviews = pr.get("review_comments", 0)
    repo    = payload.get("repository", {}).get("full_name", "unknown")

    # Rule: PR merged without review
    if action == "closed" and merged and reviews == 0 and base in ["main", "master"]:
        violations.append({
            "id":            f"V-PR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":        "GITHUB_PR",
            "event_type":    "pull_request",
            "severity":      "HIGH",
            "title":         "Pull Request merged without review",
            "description":   (
                f"PR #{pr.get('number')} merged to {base} by {user} "
                f"without any reviews in {repo}"
            ),
            "user_involved": user,
            "timestamp":     datetime.utcnow().isoformat(),
            "remediation":   "Enforce mandatory PR reviews. Require at least 1 approver before merge.",
        })

    # FIX: scan the full PR payload for compliance language.
    # spaCy phrases that fire on the test PR comment:
    #   SP004 — "no MFA"  (phrase: "no MFA")
    #   SP006 — "emergency change", "override approval", "skipping scan"
    #   SP012 — "override security" / policy bypass context
    detector_violations = _run_detectors(payload)
    violations.extend(detector_violations)

    if detector_violations:
        logger.info(
            f"[EventHandler] PR #{pr.get('number')} scan found "
            f"{len(detector_violations)} NLP/regex violation(s)"
        )

    return violations


async def handle_pr_review_event(payload: dict) -> list:
    """
    Check PR review events:
      • Dismissed review            → MEDIUM structural violation
      • Full payload NLP/regex scan → catches compliance language in review body
    """
    logger.info("[EventHandler] Checking PR review event")
    violations = []

    action = payload.get("action", "")
    user   = payload.get("sender", {}).get("login", "unknown")
    repo   = payload.get("repository", {}).get("full_name", "unknown")

    if action == "dismissed":
        violations.append({
            "id":            f"V-REVIEW-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":        "GITHUB_PR_REVIEW",
            "event_type":    "pull_request_review",
            "severity":      "MEDIUM",
            "title":         "PR review dismissed",
            "description":   f"A required review was dismissed by {user} in {repo}",
            "user_involved": user,
            "timestamp":     datetime.utcnow().isoformat(),
            "remediation":   (
                "Investigate why the review was dismissed. "
                "Ensure proper approval before merge."
            ),
        })

    # Scan review body for compliance language
    violations.extend(_run_detectors(payload))

    return violations


async def handle_pr_review_comment_event(payload: dict) -> list:
    """
    Check PR review comment events — inline code comments on a PR diff.
    Scans comment body for compliance language.
    """
    logger.info("[EventHandler] Checking PR review comment event")
    return _run_detectors(payload)


async def handle_issue_comment_event(payload: dict) -> list:
    """
    Check issue/PR comment events.
    Scans comment body for compliance language.

    This handler fires for comments on both Issues AND Pull Requests
    (GitHub sends issue_comment for both). This is the primary path that
    catches PR comments like "Skipping security scan — no MFA required".
    """
    logger.info("[EventHandler] Checking issue comment event")
    violations = _run_detectors(payload)

    if violations:
        comment_body = payload.get("comment", {}).get("body", "")[:120]
        logger.info(
            f"[EventHandler] Comment scan found {len(violations)} violation(s). "
            f"Comment preview: \"{comment_body}\""
        )

    return violations


async def handle_member_event(payload: dict) -> list:
    """Check member events — unauthorized access changes."""
    logger.info("[EventHandler] Checking member event")

    action = payload.get("action", "")
    member = payload.get("member", {}).get("login", "unknown")
    sender = payload.get("sender", {}).get("login", "unknown")
    repo   = payload.get("repository", {}).get("full_name", "unknown")

    severity = "HIGH" if action == "added" else "LOW"
    return [{
        "id":            f"V-MEMBER-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "source":        "GITHUB_MEMBER",
        "event_type":    "member",
        "severity":      severity,
        "title":         f"Repository member {action}",
        "description":   f"{member} was {action} to {repo} by {sender}",
        "user_involved": sender,
        "timestamp":     datetime.utcnow().isoformat(),
        "remediation":   "Verify this access change was approved through the proper process.",
    }]


async def handle_repository_event(payload: dict) -> list:
    """Check repository events — visibility changes, deletion, archiving."""
    logger.info("[EventHandler] Checking repository event")

    action = payload.get("action", "")
    sender = payload.get("sender", {}).get("login", "unknown")
    repo   = payload.get("repository", {}).get("full_name", "unknown")

    if action not in ["publicized", "deleted", "archived"]:
        return []

    return [{
        "id":            f"V-REPO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "source":        "GITHUB_REPO",
        "event_type":    "repository",
        "severity":      "CRITICAL" if action == "publicized" else "HIGH",
        "title":         f"Repository {action}",
        "description":   f"Repository {repo} was {action} by {sender}",
        "user_involved": sender,
        "timestamp":     datetime.utcnow().isoformat(),
        "remediation":   (
            f"Investigate the repository {action} action. "
            "Verify it was intentional and approved."
        ),
    }]


async def handle_issues_event(payload: dict) -> list:
    """
    Check issues events.
    Scans issue title and body for compliance language — also provides
    an audit trail for all issue activity.
    """
    logger.info("[EventHandler] Checking issues event")
    return _run_detectors(payload)