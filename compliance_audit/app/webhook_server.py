from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
import json
import subprocess
import sys
import os
import hmac
import hashlib
from datetime import datetime

app = FastAPI(title="Avirat Compliance Webhook Receiver")

# ── Absolute path anchors ─────────────────────────────────────
# app/webhook_server.py → go up one level to get project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBHOOK_DATA = os.path.join(ROOT, "webhook_data.json")
PIPELINE_SCRIPT = os.path.join(ROOT, "run_pipeline.py")

# ── Optional: GitHub webhook secret (set in your .env) ────────
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()


def verify_signature(body: bytes, sig_header: str) -> bool:
    """Return True if signature matches or no secret is configured."""
    if not GITHUB_SECRET:
        return True  # skip validation if secret not set
    expected = "sha256=" + hmac.new(GITHUB_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_header, expected)


def append_event(event_type: str, payload: dict):
    """Append incoming event to webhook_data.json (keeps last 50)."""
    events = []
    if os.path.exists(WEBHOOK_DATA):
        try:
            with open(WEBHOOK_DATA, "r") as f:
                data = json.load(f)
                # support both old single-object format and new list format
                events = data if isinstance(data, list) else [data]
        except (json.JSONDecodeError, IOError):
            events = []

    events.append({
        "event_type": event_type,
        "received_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "payload": payload,
    })

    # keep last 50 events so the file doesn't grow unbounded
    with open(WEBHOOK_DATA, "w") as f:
        json.dump(events[-50:], f, indent=2)


@app.post("/webhooks/github")
async def github_webhook(request: Request):
    body = await request.body()

    # ── Signature check ────────────────────────────────────────
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(body, sig_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(body)
    event_type = request.headers.get("X-GitHub-Event", "unknown_event")

    # ── Persist event to disk ──────────────────────────────────
    append_event(event_type, payload)
    print(f"\n📥 Received GitHub webhook ({event_type})! Saved to {WEBHOOK_DATA}")

    # ── Trigger pipeline ───────────────────────────────────────
    # cwd=ROOT ensures run_pipeline.py finds all JSON files at the right path
    subprocess.Popen(
        [sys.executable, PIPELINE_SCRIPT],
        cwd=ROOT,
    )
    print(f"🚀 Pipeline triggered: {PIPELINE_SCRIPT} (cwd={ROOT})")

    return {"status": "success", "message": f"Compliance pipeline triggered for {event_type}"}


@app.get("/")
async def get_dashboard():
    return HTMLResponse(
        content="""
        <h1>Webhook Server Running</h1>
        <p>Visit <a href="http://localhost:8080">http://localhost:8080</a> for the compliance dashboard.</p>
        <p>Send GitHub webhooks to <code>/webhooks/github</code>.</p>
        """
    )


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Webhook Server on port 8000...")
    print(f"   ROOT            : {ROOT}")
    print(f"   WEBHOOK_DATA    : {WEBHOOK_DATA}")
    print(f"   PIPELINE_SCRIPT : {PIPELINE_SCRIPT}")
    uvicorn.run("app.webhook_server:app", host="0.0.0.0", port=8000, reload=True)