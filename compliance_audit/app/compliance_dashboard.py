"""
compliance_dashboard.py
━━━━━━━━━━━━━━━━━━━━━━━
Live compliance dashboard — reads from MongoDB in real time.
Run: python3 compliance_dashboard.py
Open: http://localhost:8080
"""

from flask import Flask, jsonify, render_template_string
from datetime import datetime
import json
import os

app = Flask(__name__)

# ── HTML Dashboard ───────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Dashboard — Avirat.ai</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0f172a; color: #e2e8f0; font-family: Arial, sans-serif; padding: 24px; }
        h1   { color: #60a5fa; font-size: 1.8rem; margin-bottom: 4px; }
        .sub { color: #94a3b8; font-size: 0.85rem; margin-bottom: 24px; }

        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
        .card .num  { font-size: 2.5rem; font-weight: 700; }
        .card .lbl  { font-size: 0.8rem; color: #94a3b8; margin-top: 4px; }
        .critical   { color: #ef4444; }
        .high       { color: #f97316; }
        .medium     { color: #eab308; }
        .passing    { color: #22c55e; }

        .fw-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .fw-card { background: #1e293b; border-radius: 12px; padding: 16px; border: 1px solid #334155; }
        .fw-card h3 { font-size: 1rem; margin-bottom: 8px; color: #60a5fa; }
        .score-bar  { height: 8px; background: #334155; border-radius: 4px; margin: 8px 0; }
        .score-fill { height: 100%; border-radius: 4px; }

        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }
        th { background: #334155; padding: 12px 16px; text-align: left; font-size: 0.8rem; color: #94a3b8; }
        td { padding: 12px 16px; border-bottom: 1px solid #334155; font-size: 0.85rem; }
        tr:last-child td { border-bottom: none; }

        .badge { padding: 3px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 700; }
        .badge-critical { background: rgba(239,68,68,.2); color: #ef4444; }
        .badge-high     { background: rgba(249,115,22,.2); color: #f97316; }
        .badge-medium   { background: rgba(234,179,8,.2); color: #eab308; }
        .badge-low      { background: rgba(34,197,94,.2); color: #22c55e; }

        .section-title { font-size: 1rem; font-weight: 700; color: #cbd5e1; margin: 24px 0 12px; }
        .refresh { color: #475569; font-size: 0.75rem; margin-top: 24px; text-align: center; }
    </style>
</head>
<body>
    <h1>🛡️ Compliance Dashboard </h1>
    <div class="sub">Live data from Pipeline Reports · Auto-refreshes every 30 seconds · {{ generated_at }}</div>

    <!-- Summary Cards -->
    <div class="grid">
        <div class="card">
            <div class="num" style="color: {{ score_color }}">{{ overall_score }}<span style="font-size:1rem">/100</span></div>
            <div class="lbl">Overall Compliance Score</div>
        </div>
        <div class="card">
            <div class="num critical">{{ critical_count }}</div>
            <div class="lbl">🔴 Critical Violations</div>
        </div>
        <div class="card">
            <div class="num high">{{ high_count }}</div>
            <div class="lbl">🟠 High Violations</div>
        </div>
        <div class="card">
            <div class="num" style="color:#60a5fa">{{ total_violations }}</div>
            <div class="lbl">Total Violations Found</div>
        </div>
    </div>

    <!-- Framework Scores -->
    <div class="section-title">Framework Breakdown</div>
    <div class="fw-grid">
        {% for fw, data in frameworks.items() %}
        <div class="fw-card">
            <h3>{{ fw }}</h3>
            <div class="num" style="font-size:1.8rem; color:{{ data.color }}">{{ data.score }}/100</div>
            <div style="font-size:1.2rem; font-weight:bold; color:{{ data.color }}; margin: 8px 0;">{{ data.status }}</div>
            <div class="score-bar">
                <div class="score-fill" style="width:{{ data.score }}%; background:{{ data.color }}"></div>
            </div>
            <div style="font-size:0.75rem; color:#94a3b8">{{ data.violations }} violations</div>
        </div>
        {% endfor %}
    </div>

    <!-- Recent GitHub Events -->
    <div class="section-title">Recent GitHub Events (from webhook)</div>
    <table>
        <tr>
            <th>Event</th>
            <th>Action</th>
            <th>Repo</th>
            <th>User</th>
            <th>Received At</th>
        </tr>
        {% for e in github_events %}
        <tr>
            <td><span class="badge badge-high">{{ e.event_type }}</span></td>
            <td>{{ e.action }}</td>
            <td>{{ e.repo }}</td>
            <td>{{ e.user }}</td>
            <td style="color:#64748b">{{ e.received_at }}</td>
        </tr>
        {% endfor %}
        {% if not github_events %}
        <tr><td colspan="5" style="color:#475569; text-align:center">No webhook events yet — raise a PR to trigger!</td></tr>
        {% endif %}
    </table>

    <!-- Violations Table -->
    <div class="section-title">Active Violations</div>
    <table>
        <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Source</th>
            <th>Framework</th>
            <th>Status</th>
            <th>Detected At</th>
        </tr>
        {% for v in violations %}
        <tr>
            <td style="color:#64748b">{{ v.id }}</td>
            <td><span class="badge badge-{{ v.severity|lower }}">{{ v.severity }}</span></td>
            <td>{{ v.title }}</td>
            <td style="color:#94a3b8">{{ v.source }}</td>
            <td style="color:#60a5fa; font-size:0.75rem">
                {% for fw, ctrl in v.frameworks.items() %}
                    {{ fw }} 
                {% endfor %}
            </td>
            <td><span class="badge badge-high">OPEN</span></td>
            <td style="color:#64748b">{{ v.timestamp }}</td>
        </tr>
        {% endfor %}
        {% if not violations %}
        <tr><td colspan="7" style="color:#475569; text-align:center">No violations found yet</td></tr>
        {% endif %}
    </table>

    <div class="refresh">Auto-refreshes every 30 seconds · Powered by Avirat.ai</div>
</body>
</html>
"""

# ── Helper functions ─────────────────────────────────────────────
def score_color(s):
    return "#ef4444" if s < 60 else "#f97316" if s < 75 else "#eab308" if s < 90 else "#22c55e"

# ── Dashboard route ──────────────────────────────────────────────
@app.route("/")
def dashboard():
    violations = []
    frameworks = {}
    total_violations = 0
    critical_count = 0
    high_count = 0
    overall_score = 100
    
    if os.path.exists("violation_report.json"):
        with open("violation_report.json", "r") as f:
            vr = json.load(f)
            violations = vr.get("violations", [])
            total_violations = vr.get("summary", {}).get("total_violations", 0)
            critical_count = vr.get("summary", {}).get("critical", 0)
            high_count = vr.get("summary", {}).get("high", 0)
            
    if os.path.exists("framework_mapping_report.json"):
        with open("framework_mapping_report.json", "r") as f:
            fr = json.load(f)
            overall_score = fr.get("overall_score", 100)
            fw_scores = fr.get("framework_scores", {})
            fw_map = fr.get("framework_map", {})
            
            for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
                score = fw_scores.get(fw, 100)
                viols = sum(len(v) for v in fw_map.get(fw, {}).values())
                
                # PASS/FAIL logic as requested
                status = "PASS" if score >= 80 else "FAIL"
                color = "#22c55e" if status == "PASS" else "#ef4444"
                
                frameworks[fw] = {
                    "score": score,
                    "violations": viols,
                    "status": status,
                    "color": color
                }
    else:
        # Defaults if missing
        for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
            frameworks[fw] = {"score": 100, "violations": 0, "status": "PASS", "color": "#22c55e"}

    # Fetch recent GitHub events
    github_events = []
    if os.path.exists("webhook_data.json"):
        with open("webhook_data.json", "r") as f:
            payload = json.load(f)
            github_events.append({
                "event_type": "webhook",
                "action":     payload.get("action", "trigger"),
                "repo":       payload.get("repository", {}).get("full_name", "N/A"),
                "user":       payload.get("sender", {}).get("login", "N/A"),
                "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return render_template_string(
        DASHBOARD_HTML,
        overall_score    = overall_score,
        score_color      = score_color(overall_score),
        critical_count   = critical_count,
        high_count       = high_count,
        total_violations = total_violations,
        frameworks       = frameworks,
        violations       = violations,
        github_events    = github_events,
        generated_at     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

# ── API endpoint — raw data ──────────────────────────────────────
@app.route("/api/violations")
def api_violations():
    if os.path.exists("violation_report.json"):
        with open("violation_report.json", "r") as f:
            return jsonify(json.load(f).get("violations", []))
    return jsonify([])

@app.route("/api/events")
def api_events():
    if os.path.exists("webhook_data.json"):
        with open("webhook_data.json", "r") as f:
            return jsonify([json.load(f)])
    return jsonify([])

# ── Run ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Starting Compliance Dashboard...")
    print("Open: http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=True)
