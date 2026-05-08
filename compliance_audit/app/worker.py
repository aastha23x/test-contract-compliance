"""
worker.py
━━━━━━━━━
Arq async worker — picks up jobs from Redis queue and runs compliance pipeline.
Follows Gaurav's PR reviewer worker pattern.
"""

import logging
from arq import cron
from app.services.event_handler import handle_github_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ── Main task — called by webhook server ───────────────────────
async def process_github_event(ctx, event_type: str, delivery_id: str, payload: dict):
    """
    Arq job — processes a GitHub webhook event through the full compliance pipeline.
    Triggered by webhook_server.py when a GitHub event is received.
    """
    logger.info(f"[Worker] Processing event: {event_type} | delivery: {delivery_id}")

    try:
        result = await handle_github_event(event_type, delivery_id, payload)
        logger.info(f"[Worker] Done — {result.get('violations_found', 0)} violations found")
        return result

    except Exception as e:
        logger.error(f"[Worker] Error processing event {delivery_id}: {e}")
        raise


# ── Arq worker settings ────────────────────────────────────────
class WorkerSettings:
    """
    Arq worker configuration.
    Redis connection and job functions registered here.
    """
    redis_settings = None   # uses default localhost:6379

    functions = [process_github_event]

    # Optional: scheduled jobs
    # cron_jobs = [
    #     cron(scheduled_compliance_scan, hour={0}, minute={0})  # daily at midnight
    # ]

    on_startup  = None
    on_shutdown = None
    max_jobs    = 10
    job_timeout = 300   # 5 minutes max per job