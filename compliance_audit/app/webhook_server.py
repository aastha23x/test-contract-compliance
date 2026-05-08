from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import json
import subprocess
import sys
import os

app = FastAPI(title="Avirat Compliance Webhook Receiver")

@app.post("/webhooks/github")
async def github_webhook(request: Request):
    payload = await request.json()
    
    # Save the payload so the compliance agent can read it
    with open("webhook_data.json", "w") as f:
        json.dump(payload, f, indent=2)
        
    event_type = request.headers.get("X-GitHub-Event", "unknown_event")
    print(f"\n📥 Received GitHub webhook ({event_type})! Triggering compliance pipeline...")
    
    # Run the pipeline in the background so we can respond to GitHub quickly
    subprocess.Popen([sys.executable, "run_pipeline.py"])
    
    return {"status": "success", "message": f"Compliance pipeline triggered for {event_type}"}

@app.get("/")
async def get_dashboard():
    return HTMLResponse(
        content="""
        <h1>Webhook Server Running</h1>
        <p>The compliance dashboard is now a live application. Please visit <a href="http://localhost:8080">http://localhost:8080</a> to view it.</p>
        <p>Send a GitHub webhook to <code>/webhooks/github</code> to trigger the compliance scan.</p>
        """
    )

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Webhook Server on port 8000...")
    uvicorn.run("app.webhook_server:app", host="0.0.0.0", port=8000, reload=True)
