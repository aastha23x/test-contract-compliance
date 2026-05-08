"""
compliance_dashboard.py
━━━━━━━━━━━━━━━━━━━━━━━
Live compliance dashboard — reads from JSON pipeline reports in real time.
Run: python3 app/compliance_dashboard.py
Open: http://localhost:8080
"""

from flask import Flask, jsonify, render_template_string
from datetime import datetime
import json
import os

app = Flask(__name__)

# ── Absolute path anchors ─────────────────────────────────────
ROOT         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBHOOK_DATA = os.path.join(ROOT, "webhook_data.json")
VIOLATION_IN = os.path.join(ROOT, "violation_report.json")
FRAMEWORK_IN = os.path.join(ROOT, "framework_mapping_report.json")

# ── HTML Dashboard ────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="30">
  <title>Compliance Dashboard — Avirat.ai</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:       #080d14;
      --surface:  #0d1520;
      --surface2: #111d2e;
      --border:   #1e3048;
      --border2:  #243a56;
      --text:     #c8d8ec;
      --muted:    #4a6380;
      --accent:   #3b82f6;
      --critical: #ef4444;
      --high:     #f97316;
      --medium:   #eab308;
      --low:      #22c55e;
      --mono:     'JetBrains Mono', monospace;
      --sans:     'DM Sans', sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; font-size: 14px; line-height: 1.6; }

    /* Layout */
    .shell  { max-width: 1440px; margin: 0 auto; padding: 0 28px 60px; }
    .topbar {
      position: sticky; top: 0; z-index: 100;
      background: rgba(8,13,20,.96); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 14px 28px;
      display: flex; align-items: center; justify-content: space-between;
    }
    .topbar-left  { display: flex; align-items: center; gap: 14px; }
    .topbar-right { display: flex; align-items: center; gap: 12px; }
    .logo { font-family: var(--mono); font-size: 1rem; font-weight: 700; color: var(--accent); }
    .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--low); animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.3} }
    .tag {
      font-family: var(--mono); font-size: 0.7rem; font-weight: 500;
      padding: 3px 10px; border-radius: 4px;
      background: rgba(59,130,246,.1); color: var(--accent);
      border: 1px solid rgba(59,130,246,.2);
    }
    .timestamp { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); }

    /* Section headers */
    .section      { margin-top: 36px; }
    .section-head { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
    .section-head h2 { font-size: 0.78rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.5px; color: var(--muted); }
    .section-head .count { font-family: var(--mono); font-size: 0.72rem; background: var(--surface2); border: 1px solid var(--border2); padding: 2px 8px; border-radius: 4px; color: var(--text); }

    /* Hero */
    .hero       { display: grid; grid-template-columns: 210px 1fr; gap: 16px; margin-top: 28px; }
    .score-wrap {
      background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
      padding: 24px; display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .score-wrap .snum   { font-family: var(--mono); font-size: 3rem; font-weight: 700; line-height: 1; }
    .score-wrap .sdenom { font-family: var(--mono); font-size: 0.9rem; color: var(--muted); }
    .score-wrap .rlabel { margin-top: 8px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
    .score-wrap .smeta  { margin-top: 12px; font-size: 0.7rem; color: var(--muted); text-align: center; line-height: 1.7; }
    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .meta-card {
      background: var(--surface); border: 1px solid var(--border); border-top: 2px solid transparent;
      border-radius: 10px; padding: 18px 20px; transition: border-color .2s;
    }
    .meta-card:hover { border-top-color: var(--accent); }
    .meta-card .num { font-family: var(--mono); font-size: 2rem; font-weight: 700; line-height: 1; margin-bottom: 5px; }
    .meta-card .lbl { font-size: 0.75rem; color: var(--muted); font-weight: 500; }
    .meta-card .sub { font-size: 0.68rem; color: var(--muted); margin-top: 3px; opacity: .65; }

    /* Detection breakdown */
    .detect-bar  { display: flex; gap: 12px; }
    .detect-item { flex: 1; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; display: flex; align-items: center; gap: 12px; }
    .detect-icon { font-family: var(--mono); font-size: 1.1rem; font-weight: 700; min-width: 36px; }
    .detect-info .num { font-family: var(--mono); font-size: 1.5rem; font-weight: 700; line-height: 1; }
    .detect-info .lbl { font-size: 0.7rem; color: var(--muted); margin-top: 3px; }

    /* Framework grid */
    .fw-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
    .fw-card {
      background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
      padding: 18px; cursor: pointer; transition: border-color .2s, transform .15s;
    }
    .fw-card:hover  { border-color: var(--border2); transform: translateY(-2px); }
    .fw-card.active { border-color: var(--accent); }
    .fw-name   { font-family: var(--mono); font-size: 0.72rem; font-weight: 700; color: var(--muted); letter-spacing: 1px; margin-bottom: 10px; }
    .fw-score  { font-family: var(--mono); font-size: 1.7rem; font-weight: 700; line-height: 1; }
    .fw-status { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin: 6px 0 10px; }
    .fw-bar    { height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; margin-bottom: 10px; }
    .fw-bar-fill { height: 100%; border-radius: 2px; transition: width .5s; }
    .fw-ctrl-item {
      font-size: 0.68rem; color: var(--muted); padding: 3px 0;
      border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }
    .fw-ctrl-item:last-child { border-bottom: none; }
    .ctrl-badge { font-family: var(--mono); font-size: 0.6rem; padding: 1px 6px; border-radius: 3px; }

    /* Violations */
    .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; align-items: center; }
    .filter-btn {
      font-family: var(--mono); font-size: 0.7rem; font-weight: 500;
      padding: 4px 13px; border-radius: 5px; border: 1px solid var(--border2);
      background: var(--surface); color: var(--muted); cursor: pointer; transition: all .15s;
    }
    .filter-btn:hover          { border-color: var(--accent); color: var(--text); }
    .filter-btn.active         { background: var(--accent); border-color: var(--accent); color: #fff; }
    .filter-sep { width: 1px; height: 20px; background: var(--border2); }

    .vtable-wrap { border-radius: 10px; border: 1px solid var(--border); overflow: hidden; }
    table { width: 100%; border-collapse: collapse; }
    thead th {
      background: var(--surface2); padding: 10px 14px;
      text-align: left; font-size: 0.66rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 1px; color: var(--muted);
      border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    tbody tr.vrow             { background: var(--surface); cursor: pointer; transition: background .1s; }
    tbody tr.vrow:hover       { background: var(--surface2); }
    tbody tr.vrow td          { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.8rem; vertical-align: middle; }
    .expand-row td            { padding: 0; border-bottom: 1px solid var(--border); background: #0a1422; }
    .expand-inner             { padding: 20px 24px; display: none; }
    .expand-inner.open        { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    .expand-block h4          { font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 8px; }
    .expand-block p           { font-size: 0.8rem; color: var(--text); line-height: 1.75; }
    .matched-evidence {
      font-family: var(--mono); font-size: 0.72rem;
      background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.18);
      color: #fca5a5; padding: 8px 12px; border-radius: 6px;
      margin-top: 10px; word-break: break-all;
    }
    .ctrl-chips { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 10px; }
    .ctrl-chip  {
      font-family: var(--mono); font-size: 0.62rem;
      padding: 2px 8px; border-radius: 3px;
      background: var(--surface2); color: var(--muted);
      border: 1px solid var(--border2);
    }
    .fw-chip {
      font-family: var(--mono); font-size: 0.62rem; font-weight: 600;
      padding: 2px 8px; border-radius: 3px;
      background: rgba(59,130,246,.1); color: var(--accent);
      border: 1px solid rgba(59,130,246,.18);
    }
    .meta-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .meta-pill { font-size: 0.68rem; color: var(--muted); }
    .chevron { color: var(--muted); font-size: 0.7rem; transition: transform .2s; }
    .chevron.open { transform: rotate(180deg); }

    /* Badges */
    .sev { font-family: var(--mono); font-size: 0.63rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: .5px; white-space: nowrap; }
    .sev-CRITICAL { background: rgba(239,68,68,.15); color: var(--critical); border: 1px solid rgba(239,68,68,.25); }
    .sev-HIGH     { background: rgba(249,115,22,.15); color: var(--high);     border: 1px solid rgba(249,115,22,.25); }
    .sev-MEDIUM   { background: rgba(234,179,8,.15);  color: var(--medium);   border: 1px solid rgba(234,179,8,.25); }
    .sev-LOW      { background: rgba(34,197,94,.15);  color: var(--low);      border: 1px solid rgba(34,197,94,.25); }
    .det-badge { font-family: var(--mono); font-size: 0.6rem; font-weight: 600; padding: 2px 7px; border-radius: 3px; }
    .det-REGEX { background: rgba(168,85,247,.12); color: #c084fc; border: 1px solid rgba(168,85,247,.2); }
    .det-SPACY { background: rgba(20,184,166,.12);  color: #2dd4bf; border: 1px solid rgba(20,184,166,.2); }
    .det-LLM   { background: rgba(59,130,246,.12);  color: var(--accent); border: 1px solid rgba(59,130,246,.2); }

    /* Events */
    .event-wrap { border-radius: 10px; border: 1px solid var(--border); overflow: hidden; }
    tbody tr.erow td   { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
    tbody tr.erow:last-child td { border-bottom: none; }
    .event-type { font-family: var(--mono); font-size: 0.66rem; font-weight: 600; padding: 2px 8px; border-radius: 4px; background: rgba(59,130,246,.1); color: var(--accent); border: 1px solid rgba(59,130,246,.18); }
    .sha { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); }

    /* Pipeline health */
    .health-bar  { display: flex; gap: 12px; }
    .health-item { flex: 1; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
    .health-item .hlbl { font-size: 0.66rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); font-weight: 600; margin-bottom: 6px; }
    .health-item .hval { font-family: var(--mono); font-size: 0.88rem; font-weight: 600; }
    .health-ok   { color: var(--low); }
    .health-warn { color: var(--medium); }
    .health-fail { color: var(--critical); }

    /* Priority fixes */
    .pfix-list { display: flex; flex-direction: column; gap: 10px; }
    .pfix-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; display: flex; gap: 14px; align-items: flex-start; }
    .pfix-rank { font-family: var(--mono); font-size: 0.72rem; font-weight: 700; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px; }
    .pfix-body .ptitle { font-size: 0.83rem; font-weight: 600; margin-bottom: 4px; }
    .pfix-body .premed { font-size: 0.76rem; color: var(--muted); line-height: 1.55; }

    /* Empty states */
    .empty { padding: 32px; text-align: center; color: var(--muted); font-size: 0.8rem; }
    .empty-icon { font-size: 1.6rem; margin-bottom: 8px; opacity: .35; }

    /* Footer */
    .footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; font-size: 0.7rem; color: var(--muted); font-family: var(--mono); }
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
  </style>
</head>
<body>

<div class="topbar">
  <div class="topbar-left">
    <span class="logo">avirat.ai</span>
    <span class="live-dot" title="Auto-refreshes every 30s"></span>
    <span class="tag">Compliance Monitor</span>
  </div>
  <div class="topbar-right">
    <span class="timestamp">{{ generated_at }}</span>
    <span class="tag" style="background:rgba(34,197,94,.08);color:var(--low);border-color:rgba(34,197,94,.2)">{{ pipeline_status }}</span>
  </div>
</div>

<div class="shell">

  <!-- Hero: score + severity breakdown -->
  <div class="hero">
    <div class="score-wrap">
      <div class="snum" style="color:{{ score_color }}">{{ overall_score }}</div>
      <div class="sdenom">/100</div>
      <div class="rlabel" style="color:{{ score_color }}">{{ risk_level }}</div>
      <div class="smeta">Last scan: {{ last_scan }}<br>{{ total_violations }} violation{{ 's' if total_violations != 1 else '' }} detected</div>
    </div>
    <div class="meta-grid">
      <div class="meta-card">
        <div class="num" style="color:var(--critical)">{{ critical_count }}</div>
        <div class="lbl">Critical</div>
        <div class="sub">Immediate action</div>
      </div>
      <div class="meta-card">
        <div class="num" style="color:var(--high)">{{ high_count }}</div>
        <div class="lbl">High</div>
        <div class="sub">Fix within 24h</div>
      </div>
      <div class="meta-card">
        <div class="num" style="color:var(--medium)">{{ medium_count }}</div>
        <div class="lbl">Medium</div>
        <div class="sub">Fix within 7 days</div>
      </div>
      <div class="meta-card">
        <div class="num" style="color:var(--low)">{{ low_count }}</div>
        <div class="lbl">Low</div>
        <div class="sub">Fix within 30 days</div>
      </div>
    </div>
  </div>

  <!-- Detection engine breakdown -->
  <div class="section">
    <div class="section-head"><h2>Detection Engine</h2></div>
    <div class="detect-bar">
      <div class="detect-item">
        <div class="detect-icon" style="color:#c084fc">RX</div>
        <div class="detect-info">
          <div class="num" style="color:#c084fc">{{ regex_detections }}</div>
          <div class="lbl">Regex (structural patterns)</div>
        </div>
      </div>
      <div class="detect-item">
        <div class="detect-icon" style="color:#2dd4bf">NLP</div>
        <div class="detect-info">
          <div class="num" style="color:#2dd4bf">{{ spacy_detections }}</div>
          <div class="lbl">spaCy (NLP phrases + NER)</div>
        </div>
      </div>
      <div class="detect-item">
        <div class="detect-icon" style="color:var(--accent)">LLM</div>
        <div class="detect-info">
          <div class="num" style="color:var(--accent)">{{ llm_detections }}</div>
          <div class="lbl">LLM enrichments applied</div>
        </div>
      </div>
      <div class="detect-item">
        <div class="detect-icon" style="color:var(--muted)">EVT</div>
        <div class="detect-info">
          <div class="num" style="color:var(--text)">{{ event_count }}</div>
          <div class="lbl">GitHub events scanned</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Framework compliance -->
  <div class="section">
    <div class="section-head"><h2>Framework Compliance</h2></div>
    <div class="fw-grid">
      {% for fw, data in frameworks.items() %}
      <div class="fw-card" id="fw-{{ fw }}" onclick="filterByFramework('{{ fw }}')">
        <div class="fw-name">{{ fw }}</div>
        <div class="fw-score" style="color:{{ data.color }}">{{ data.score }}<span style="font-size:0.85rem;color:var(--muted)">/100</span></div>
        <div class="fw-status" style="color:{{ data.color }}">{{ data.status }}</div>
        <div class="fw-bar"><div class="fw-bar-fill" style="width:{{ data.score }}%;background:{{ data.color }}"></div></div>
        <div style="font-size:0.68rem;color:var(--muted);margin-bottom:10px">
          {{ data.violations }} violation{{ 's' if data.violations != 1 else '' }}
          &nbsp;·&nbsp;
          {{ data.controls_hit }} control{{ 's' if data.controls_hit != 1 else '' }} affected
        </div>
        {% if data.controls %}
        <div>
          {% for ctrl in data.controls[:4] %}
          <div class="fw-ctrl-item">
            <span style="font-family:var(--mono);font-size:0.63rem;color:var(--text)">{{ ctrl.id }}</span>
            <span class="ctrl-badge sev-{{ ctrl.severity }}">{{ ctrl.severity }}</span>
          </div>
          {% endfor %}
          {% if data.controls|length > 4 %}
          <div style="font-size:0.63rem;color:var(--muted);padding-top:4px">+{{ data.controls|length - 4 }} more</div>
          {% endif %}
        </div>
        {% else %}
        <div style="font-size:0.68rem;color:var(--low)">✓ No controls affected</div>
        {% endif %}
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- Priority remediation -->
  {% if priority_fixes %}
  <div class="section">
    <div class="section-head">
      <h2>Priority Remediation</h2>
      <span class="count">Top {{ [priority_fixes|length, 5]|min }}</span>
    </div>
    <div class="pfix-list">
      {% for fix in priority_fixes[:5] %}
      <div class="pfix-item">
        <div class="pfix-rank" style="background:rgba({{ sev_rgb.get(fix.severity,'59,130,246') }},.15);color:{{ sev_colors.get(fix.severity,'#3b82f6') }}">{{ fix.rank }}</div>
        <div style="padding-top:2px"><span class="sev sev-{{ fix.severity }}">{{ fix.severity }}</span></div>
        <div class="pfix-body">
          <div class="ptitle">{{ fix.title }}</div>
          <div class="premed">{{ fix.remediation }}</div>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- Violations table -->
  <div class="section">
    <div class="section-head">
      <h2>Active Violations</h2>
      <span class="count">{{ total_violations }}</span>
    </div>
    <div class="filter-bar">
      <button class="filter-btn active" id="btn-all"      onclick="filterTable('all')">All ({{ total_violations }})</button>
      <button class="filter-btn"        id="btn-CRITICAL" onclick="filterTable('CRITICAL')">Critical ({{ critical_count }})</button>
      <button class="filter-btn"        id="btn-HIGH"     onclick="filterTable('HIGH')">High ({{ high_count }})</button>
      <button class="filter-btn"        id="btn-MEDIUM"   onclick="filterTable('MEDIUM')">Medium ({{ medium_count }})</button>
      <button class="filter-btn"        id="btn-LOW"      onclick="filterTable('LOW')">Low ({{ low_count }})</button>
      <div class="filter-sep"></div>
      <button class="filter-btn" id="btn-REGEX" onclick="filterByDetector('REGEX')">Regex</button>
      <button class="filter-btn" id="btn-SPACY" onclick="filterByDetector('SPACY')">spaCy</button>
    </div>
    <div class="vtable-wrap">
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>ID</th><th>Title</th><th>Rule</th>
            <th>Detector</th><th>User</th><th>Frameworks</th><th>Detected</th><th></th>
          </tr>
        </thead>
        <tbody id="vtbody">
          {% if violations %}
            {% for v in violations %}
            <tr class="vrow" data-sev="{{ v.severity }}" data-det="{{ v.get('detection','LLM') }}" onclick="toggleV('{{ v.id }}')">
              <td><span class="sev sev-{{ v.severity }}">{{ v.severity }}</span></td>
              <td><span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">{{ v.id }}</span></td>
              <td style="font-weight:500;max-width:260px">{{ v.title }}</td>
              <td><span style="font-family:var(--mono);font-size:0.68rem;color:var(--muted)">{{ v.get('rule_id','—') }}</span></td>
              <td><span class="det-badge det-{{ v.get('detection','LLM') }}">{{ v.get('detection','LLM') }}</span></td>
              <td style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">{{ v.get('user_involved','—') }}</td>
              <td>
                <div style="display:flex;gap:4px;flex-wrap:wrap">
                  {% for fw in v.get('frameworks',{}).keys() %}<span class="fw-chip">{{ fw }}</span>{% endfor %}
                </div>
              </td>
              <td style="font-family:var(--mono);font-size:0.68rem;color:var(--muted);white-space:nowrap">{{ v.get('timestamp','—')[:16] }}</td>
              <td><span class="chevron" id="chev-{{ v.id }}">▼</span></td>
            </tr>
            <tr class="expand-row" id="exp-{{ v.id }}">
              <td colspan="9">
                <div class="expand-inner" id="inner-{{ v.id }}">
                  <div class="expand-block">
                    <h4>Description &amp; Evidence</h4>
                    <p>{{ v.get('description','No description available.') }}</p>
                    {% if v.get('matched_text') %}
                    <div class="matched-evidence">Matched: {{ v.matched_text }}</div>
                    {% endif %}
                    <div class="ctrl-chips">
                      {% for fw, ctrl in v.get('frameworks',{}).items() %}
                        {% if ctrl and ctrl != 'null' %}
                        <span class="ctrl-chip">{{ fw }}: {{ ctrl }}</span>
                        {% endif %}
                      {% endfor %}
                    </div>
                  </div>
                  <div class="expand-block">
                    <h4>Remediation Steps</h4>
                    <p>{{ v.get('remediation','No remediation steps available.') }}</p>
                    <div class="meta-row">
                      <span class="meta-pill">Source: {{ v.get('source','—') }}</span>
                      <span class="meta-pill">·</span>
                      <span class="meta-pill">Rule: {{ v.get('rule_id','—') }}</span>
                      <span class="meta-pill">·</span>
                      <span class="meta-pill">Detector: {{ v.get('detection','—') }}</span>
                      <span class="meta-pill">·</span>
                      <span class="meta-pill">Status: OPEN</span>
                    </div>
                  </div>
                </div>
              </td>
            </tr>
            {% endfor %}
          {% else %}
          <tr><td colspan="9"><div class="empty"><div class="empty-icon">✓</div>No violations detected — system is compliant</div></td></tr>
          {% endif %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- GitHub events -->
  <div class="section">
    <div class="section-head">
      <h2>Recent GitHub Events</h2>
      <span class="count">{{ github_events|length }}</span>
    </div>
    <div class="event-wrap">
      <table>
        <thead>
          <tr><th>Event</th><th>Action</th><th>Repository</th><th>User</th><th>Ref / PR</th><th>Commits</th><th>Received</th></tr>
        </thead>
        <tbody>
          {% if github_events %}
            {% for e in github_events %}
            <tr class="erow">
              <td><span class="event-type">{{ e.event_type }}</span></td>
              <td style="color:var(--muted);font-size:0.78rem">{{ e.action }}</td>
              <td style="font-family:var(--mono);font-size:0.72rem">{{ e.repo }}</td>
              <td style="font-family:var(--mono);font-size:0.72rem;color:var(--accent)">{{ e.user }}</td>
              <td><span class="sha">{{ e.ref }}</span></td>
              <td style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">{{ e.commits }}</td>
              <td style="font-family:var(--mono);font-size:0.7rem;color:var(--muted)">{{ e.received_at }}</td>
            </tr>
            {% endfor %}
          {% else %}
          <tr><td colspan="7"><div class="empty"><div class="empty-icon">◎</div>No webhook events yet — raise a PR to trigger</div></td></tr>
          {% endif %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Pipeline health -->
  <div class="section">
    <div class="section-head"><h2>Pipeline Health</h2></div>
    <div class="health-bar">
      <div class="health-item">
        <div class="hlbl">Layer 1 — Scan</div>
        <div class="hval {{ 'health-ok' if health.layer1 else 'health-fail' }}">{{ '✓ OK' if health.layer1 else '✗ No data' }}</div>
      </div>
      <div class="health-item">
        <div class="hlbl">Layer 2 — Framework Map</div>
        <div class="hval {{ 'health-ok' if health.layer2 else 'health-fail' }}">{{ '✓ OK' if health.layer2 else '✗ No data' }}</div>
      </div>
      <div class="health-item">
        <div class="hlbl">Webhook Data</div>
        <div class="hval {{ 'health-ok' if health.webhook else 'health-warn' }}">{{ '✓ Receiving' if health.webhook else '⚠ None yet' }}</div>
      </div>
      <div class="health-item">
        <div class="hlbl">Last Scan Age</div>
        <div class="hval {{ 'health-ok' if health.fresh else 'health-warn' }}">{{ health.scan_age }}</div>
      </div>
      <div class="health-item">
        <div class="hlbl">Frameworks Passing</div>
        <div class="hval health-ok">{{ health.passing_fw }}/4</div>
      </div>
    </div>
  </div>

  <div class="footer">
    avirat.ai compliance monitor &nbsp;·&nbsp; azure openai gpt-4o &nbsp;·&nbsp;
    iso27001 · soc2 · hipaa · gdpr &nbsp;·&nbsp;
    auto-refreshes every 30s &nbsp;·&nbsp; {{ generated_at }}
  </div>
</div>

<script>
function toggleV(id) {
  const inner = document.getElementById('inner-' + id);
  const chev  = document.getElementById('chev-'  + id);
  const isOpen = inner.classList.contains('open');
  document.querySelectorAll('.expand-inner.open').forEach(el => el.classList.remove('open'));
  document.querySelectorAll('.chevron.open').forEach(el => el.classList.remove('open'));
  if (!isOpen) { inner.classList.add('open'); chev.classList.add('open'); }
}

function _setRows(testFn) {
  document.querySelectorAll('.vrow').forEach(row => {
    const show    = testFn(row);
    const onclick = row.getAttribute('onclick') || '';
    const match   = onclick.match(/'([^']+)'/);
    const vid     = match ? match[1] : null;
    row.style.display = show ? '' : 'none';
    if (vid) {
      const expRow = document.getElementById('exp-' + vid);
      if (expRow) expRow.style.display = show ? '' : 'none';
      if (!show) {
        const inner = document.getElementById('inner-' + vid);
        const chev  = document.getElementById('chev-'  + vid);
        if (inner) inner.classList.remove('open');
        if (chev)  chev.classList.remove('open');
      }
    }
  });
}

function filterTable(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + sev)?.classList.add('active');
  document.querySelectorAll('.fw-card').forEach(c => c.classList.remove('active'));
  _setRows(row => sev === 'all' || row.dataset.sev === sev);
}

function filterByDetector(det) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + det)?.classList.add('active');
  document.querySelectorAll('.fw-card').forEach(c => c.classList.remove('active'));
  _setRows(row => row.dataset.det === det);
}

function filterByFramework(fw) {
  document.querySelectorAll('.fw-card').forEach(c => c.classList.remove('active'));
  document.getElementById('fw-' + fw)?.classList.add('active');
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  _setRows(row => {
    const chips = Array.from(row.querySelectorAll('.fw-chip')).map(t => t.textContent.trim());
    return chips.includes(fw);
  });
  document.querySelector('.vtable-wrap')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
</script>
</body>
</html>
"""

# ── Helpers ───────────────────────────────────────────────────
SEV_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
SEV_RGB    = {"CRITICAL": "239,68,68", "HIGH": "249,115,22", "MEDIUM": "234,179,8", "LOW": "34,197,94"}


def score_color(s: int) -> str:
    return "#ef4444" if s < 60 else "#f97316" if s < 75 else "#eab308" if s < 90 else "#22c55e"


def risk_level(s: int) -> str:
    return "CRITICAL RISK" if s < 60 else "HIGH RISK" if s < 75 else "MEDIUM RISK" if s < 90 else "PASSING"


def scan_age(generated_at_iso: str) -> tuple[str, bool]:
    try:
        delta = (datetime.utcnow() - datetime.fromisoformat(generated_at_iso)).total_seconds()
        if delta < 60:    return "< 1 min ago", True
        if delta < 3600:  return f"{int(delta//60)} min ago", True
        return f"{int(delta//3600)}h ago", False
    except Exception:
        return "unknown", False


def load_webhook_events() -> list:
    if not os.path.exists(WEBHOOK_DATA):
        return []
    try:
        with open(WEBHOOK_DATA) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

    entries = raw if isinstance(raw, list) else [{"payload": raw}]
    events  = []
    for entry in entries:
        payload    = entry.get("payload", entry)
        event_type = entry.get("event_type", "webhook")
        received   = entry.get("received_at", "—")
        ref = (
            payload.get("ref", "")
            or (f"PR #{payload['pull_request']['number']}" if isinstance(payload.get("pull_request"), dict) else "")
            or "—"
        )
        events.append({
            "event_type": event_type,
            "action":     payload.get("action", "—"),
            "repo":       payload.get("repository", {}).get("full_name", "N/A"),
            "user":       payload.get("sender", {}).get("login", "N/A"),
            "ref":        str(ref)[:40],
            "commits":    str(len(payload.get("commits", []))) if payload.get("commits") else "—",
            "received_at": received,
        })
    return list(reversed(events))[:20]


def build_framework_data(fw_scores: dict, fw_map: dict) -> dict:
    result = {}
    for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
        score  = fw_scores.get(fw, 100)
        status = "PASS" if score >= 80 else "FAIL"
        color  = "#22c55e" if status == "PASS" else "#ef4444"
        controls = []
        for ctrl_id, viols in fw_map.get(fw, {}).items():
            if viols:
                worst = min(viols, key=lambda v: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(v.get("severity","LOW"),3))
                controls.append({"id": ctrl_id, "severity": worst.get("severity","LOW"), "count": len(viols)})
        result[fw] = {
            "score":        score,
            "violations":   sum(len(v) for v in fw_map.get(fw, {}).values()),
            "controls_hit": len(fw_map.get(fw, {})),
            "status":       status,
            "color":        color,
            "controls":     sorted(controls, key=lambda c: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(c["severity"],3)),
        }
    return result


def build_health(vr_exists, fr_exists, webhook_exists, fr_generated_at, frameworks) -> object:
    age_str, fresh = scan_age(fr_generated_at) if fr_generated_at else ("never", False)
    passing = sum(1 for d in frameworks.values() if d["status"] == "PASS")

    class Health:
        layer1     = vr_exists
        layer2     = fr_exists
        webhook    = webhook_exists
        scan_age   = age_str
        passing_fw = passing

    Health.fresh = fresh
    return Health


# ── Dashboard route ───────────────────────────────────────────
@app.route("/")
def dashboard():
    violations     = []
    summary        = {}
    frameworks     = {}
    overall_score  = 100
    priority_fixes = []
    fr_generated_at = ""

    vr_exists = os.path.exists(VIOLATION_IN)
    fr_exists = os.path.exists(FRAMEWORK_IN)

    if vr_exists:
        with open(VIOLATION_IN) as f:
            vr = json.load(f)
        violations = vr.get("violations", [])
        summary    = vr.get("summary", {})

    if fr_exists:
        with open(FRAMEWORK_IN) as f:
            fr = json.load(f)
        overall_score    = fr.get("overall_score", 100)
        priority_fixes   = fr.get("priority_fixes", [])
        fr_generated_at  = fr.get("generated_at", "")
        frameworks       = build_framework_data(fr.get("framework_scores", {}), fr.get("framework_map", {}))
    else:
        for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
            frameworks[fw] = {"score":100,"violations":0,"controls_hit":0,"status":"PASS","color":"#22c55e","controls":[]}

    github_events   = load_webhook_events()
    health          = build_health(vr_exists, fr_exists, os.path.exists(WEBHOOK_DATA), fr_generated_at, frameworks)
    pipeline_status = f"{health.passing_fw}/4 frameworks passing"

    return render_template_string(
        DASHBOARD_HTML,
        overall_score    = overall_score,
        score_color      = score_color(overall_score),
        risk_level       = risk_level(overall_score),
        total_violations = summary.get("total_violations", 0),
        critical_count   = summary.get("critical", 0),
        high_count       = summary.get("high", 0),
        medium_count     = summary.get("medium", 0),
        low_count        = summary.get("low", 0),
        regex_detections = summary.get("regex_detections", 0),
        spacy_detections = summary.get("spacy_detections", 0),
        llm_detections   = summary.get("llm_detections", 0),
        event_count      = len(github_events),
        frameworks       = frameworks,
        violations       = violations,
        github_events    = github_events,
        priority_fixes   = priority_fixes,
        sev_colors       = SEV_COLORS,
        sev_rgb          = SEV_RGB,
        health           = health,
        last_scan        = fr_generated_at[:16].replace("T", " ") if fr_generated_at else "never",
        pipeline_status  = pipeline_status,
        generated_at     = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


# ── API endpoints ─────────────────────────────────────────────
@app.route("/api/violations")
def api_violations():
    if os.path.exists(VIOLATION_IN):
        with open(VIOLATION_IN) as f:
            return jsonify(json.load(f).get("violations", []))
    return jsonify([])

@app.route("/api/summary")
def api_summary():
    if os.path.exists(VIOLATION_IN):
        with open(VIOLATION_IN) as f:
            return jsonify(json.load(f).get("summary", {}))
    return jsonify({})

@app.route("/api/frameworks")
def api_frameworks():
    if os.path.exists(FRAMEWORK_IN):
        with open(FRAMEWORK_IN) as f:
            return jsonify(json.load(f))
    return jsonify({})

@app.route("/api/events")
def api_events():
    return jsonify(load_webhook_events())

@app.route("/api/health")
def api_health():
    vr_exists = os.path.exists(VIOLATION_IN)
    fr_exists = os.path.exists(FRAMEWORK_IN)
    fr_generated_at = ""
    frameworks = {}
    if fr_exists:
        with open(FRAMEWORK_IN) as f:
            fr = json.load(f)
        fr_generated_at = fr.get("generated_at", "")
        frameworks = build_framework_data(fr.get("framework_scores", {}), fr.get("framework_map", {}))
    health = build_health(vr_exists, fr_exists, os.path.exists(WEBHOOK_DATA), fr_generated_at, frameworks)
    return jsonify({
        "layer1": health.layer1, "layer2": health.layer2,
        "webhook": health.webhook, "fresh": health.fresh,
        "scan_age": health.scan_age, "passing_fw": health.passing_fw,
    })


# ── Run ───────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Starting Compliance Dashboard...")
    print(f"   ROOT         : {ROOT}")
    print(f"   VIOLATION_IN : {VIOLATION_IN}")
    print(f"   FRAMEWORK_IN : {FRAMEWORK_IN}")
    print(f"   WEBHOOK_DATA : {WEBHOOK_DATA}")
    print("Open: http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=True)