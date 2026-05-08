"""
event_handler.py
━━━━━━━━━━━━━━━━
Routes GitHub webhook events to the correct compliance checks.
Orchestrates the full pipeline: detect → map → create ticket → log.
"""

import logging
from datetime import datetime
from pymongo import MongoClient

from app.services.detectors.regex_detector import RegexDetector
from app.services.detectors.spacy_detector import SpacyDetector
from app.services.compliance_agent import run_compliance_agent
from app.services.framework_mapper import run_framework_mapper
from app.services.jira_creator import create_jira_tickets
from app.services.audit_logger import log_audit_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── MongoDB ────────────────────────────────────────────────────
mongo_client = MongoClient("mongodb://localhost:27017/")
db           = mongo_client["jira_audit_db"]


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

    elif event_type == "member":
        violations = await handle_member_event(payload)

    elif event_type == "repository":
        violations = await handle_repository_event(payload)

    elif event_type == "issues":
        violations = await handle_issues_event(payload)

    elif event_type == "issue_comment":
        violations = await handle_issue_comment_event(payload)

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

        # Create Jira tickets
        jira_tickets = create_jira_tickets(mapped_violations)

        logger.info(f"[EventHandler] {len(violations)} violations found, {len(jira_tickets)} tickets created")

    # Log audit event
    duration = (datetime.utcnow() - start_time).total_seconds()
    await log_audit_event(event_type, delivery_id, len(violations), jira_tickets, duration)

    return {
        "event_type":       event_type,
        "delivery_id":      delivery_id,
        "violations_found": len(violations),
        "jira_tickets":     jira_tickets,
        "duration_seconds": duration
    }


# ── Event handlers ─────────────────────────────────────────────
async def handle_push_event(payload: dict) -> list:
    """Check push events — direct pushes to main, after hours commits"""
    logger.info("[EventHandler] Checking push event")
    violations = []

    ref     = payload.get("ref", "")
    pusher  = payload.get("pusher", {}).get("name", "unknown")
    commits = payload.get("commits", [])
    repo    = payload.get("repository", {}).get("full_name", "unknown")

    # Rule 1 — direct push to main
    if ref in ["refs/heads/main", "refs/heads/master"]:
        violations.append({
            "id":           f"V-PUSH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":       "GITHUB_PUSH",
            "event_type":   "push",
            "severity":     "CRITICAL",
            "title":        "Direct push to main branch — bypassed PR process",
            "description":  f"{pusher} pushed {len(commits)} commit(s) directly to {ref} in {repo}",
            "user_involved": pusher,
            "timestamp":    datetime.utcnow().isoformat(),
            "remediation":  "Enable branch protection. Require PRs for all changes to main."
        })

    # Rule 2 — after hours push
    hour = datetime.utcnow().hour
    if hour < 8 or hour > 22:
        violations.append({
            "id":           f"V-HOURS-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":       "GITHUB_PUSH",
            "event_type":   "push",
            "severity":     "MEDIUM",
            "title":        "Code pushed outside business hours",
            "description":  f"{pusher} pushed to {repo} at {datetime.utcnow().strftime('%H:%M')} UTC",
            "user_involved": pusher,
            "timestamp":    datetime.utcnow().isoformat(),
            "remediation":  "Investigate the push. Verify it was not a compromised account."
        })

    # Run regex + spacy on commit messages and diff
    for commit in commits:
        message = commit.get("message", "")
        regex_violations  = RegexDetector().detect(message)
        spacy_violations  = SpacyDetector().detect(message)
        violations.extend(regex_violations + spacy_violations)

    return violations


async def handle_pull_request_event(payload: dict) -> list:
    """Check PR events — unreviewed merges, missing approvals"""
    logger.info("[EventHandler] Checking pull request event")
    violations = []

    action  = payload.get("action", "")
    pr      = payload.get("pull_request", {})
    user    = pr.get("user", {}).get("login", "unknown")
    merged  = pr.get("merged", False)
    base    = pr.get("base", {}).get("ref", "")
    reviews = pr.get("review_comments", 0)
    repo    = payload.get("repository", {}).get("full_name", "unknown")

    # PR merged without review
    if action == "closed" and merged and reviews == 0 and base in ["main", "master"]:
        violations.append({
            "id":           f"V-PR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":       "GITHUB_PR",
            "event_type":   "pull_request",
            "severity":     "HIGH",
            "title":        "Pull Request merged without review",
            "description":  f"PR #{pr.get('number')} merged to {base} by {user} without any reviews in {repo}",
            "user_involved": user,
            "timestamp":    datetime.utcnow().isoformat(),
            "remediation":  "Enforce mandatory PR reviews. Require at least 1 approver before merge."
        })

    return violations


async def handle_pr_review_event(payload: dict) -> list:
    """Check PR review events — dismissed reviews"""
    logger.info("[EventHandler] Checking PR review event")
    violations = []

    action  = payload.get("action", "")
    review  = payload.get("review", {})
    state   = review.get("state", "")
    user    = payload.get("sender", {}).get("login", "unknown")
    repo    = payload.get("repository", {}).get("full_name", "unknown")

    if action == "dismissed":
        violations.append({
            "id":           f"V-REVIEW-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":       "GITHUB_PR_REVIEW",
            "event_type":   "pull_request_review",
            "severity":     "MEDIUM",
            "title":        "PR review dismissed",
            "description":  f"A required review was dismissed by {user} in {repo}",
            "user_involved": user,
            "timestamp":    datetime.utcnow().isoformat(),
            "remediation":  "Investigate why the review was dismissed. Ensure proper approval before merge."
        })

    return violations


async def handle_member_event(payload: dict) -> list:
    """Check member events — unauthorized access changes"""
    logger.info("[EventHandler] Checking member event")
    violations = []

    action = payload.get("action", "")
    member = payload.get("member", {}).get("login", "unknown")
    sender = payload.get("sender", {}).get("login", "unknown")
    repo   = payload.get("repository", {}).get("full_name", "unknown")

    severity = "HIGH" if action == "added" else "LOW"
    violations.append({
        "id":           f"V-MEMBER-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "source":       "GITHUB_MEMBER",
        "event_type":   "member",
        "severity":     severity,
        "title":        f"Repository member {action}",
        "description":  f"{member} was {action} to {repo} by {sender}",
        "user_involved": sender,
        "timestamp":    datetime.utcnow().isoformat(),
        "remediation":  "Verify this access change was approved through the proper process."
    })

    return violations


async def handle_repository_event(payload: dict) -> list:
    """Check repository events — visibility changes, deletion"""
    logger.info("[EventHandler] Checking repository event")
    violations = []

    action = payload.get("action", "")
    sender = payload.get("sender", {}).get("login", "unknown")
    repo   = payload.get("repository", {}).get("full_name", "unknown")

    if action in ["publicized", "deleted", "archived"]:
        violations.append({
            "id":           f"V-REPO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source":       "GITHUB_REPO",
            "event_type":   "repository",
            "severity":     "CRITICAL" if action == "publicized" else "HIGH",
            "title":        f"Repository {action}",
            "description":  f"Repository {repo} was {action} by {sender}",
            "user_involved": sender,
            "timestamp":    datetime.utcnow().isoformat(),
            "remediation":  f"Investigate the repository {action} action. Verify it was intentional and approved."
        })

    return violations


async def handle_issues_event(payload: dict) -> list:
    """Check issues events — compliance ticket tracking"""
    logger.info("[EventHandler] Checking issues event")
    # Issues don't typically trigger violations
    # but we log them for audit trail
    return []


async def handle_issue_comment_event(payload: dict) -> list:
    """Check issue comment events — audit trail"""
    logger.info("[EventHandler] Checking issue comment event")
    return []