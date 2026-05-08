"""
audit_logger.py
━━━━━━━━━━━━━━━
Logs every compliance scan run to MongoDB.
Same pattern as Gaurav's audit_logger.py.
"""

import logging
from datetime import datetime
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── MongoDB ────────────────────────────────────────────────────
mongo_client = MongoClient("mongodb://localhost:27017/")
db           = mongo_client["jira_audit_db"]


async def log_audit_event(
    event_type:       str,
    delivery_id:      str,
    violations_found: int,
    jira_tickets:     list,
    duration_seconds: float
):
    """
    Log every compliance scan run to MongoDB audit_logs collection.
    Used for tracking scan history, performance, and remediation velocity.
    """
    log_entry = {
        "event_type":        event_type,
        "delivery_id":       delivery_id,
        "violations_found":  violations_found,
        "jira_tickets":      jira_tickets,
        "duration_seconds":  round(duration_seconds, 3),
        "logged_at":         datetime.utcnow().isoformat(),
        "status":            "completed"
    }

    try:
        db["audit_logs"].insert_one(log_entry)
        logger.info(f"[AuditLogger] Logged scan — {violations_found} violations in {duration_seconds:.2f}s")
    except Exception as e:
        logger.error(f"[AuditLogger] Failed to log: {e}")


def get_recent_logs(limit: int = 50) -> list:
    """Fetch recent audit logs for dashboard display"""
    logs = list(db["audit_logs"].find(
        {},
        {"_id": 0}
    ).sort("logged_at", -1).limit(limit))
    return logs


def get_scan_stats() -> dict:
    """Get overall scan statistics"""
    total_scans      = db["audit_logs"].count_documents({})
    total_violations = db["violations"].count_documents({})
    open_violations  = db["violations"].count_documents({"status": "OPEN"})
    total_tickets    = db["violations"].count_documents({"jira_ticket": {"$ne": None}})

    return {
        "total_scans":      total_scans,
        "total_violations": total_violations,
        "open_violations":  open_violations,
        "tickets_created":  total_tickets
    }