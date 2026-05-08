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
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,300;0,9..144,600;1,9..144,300&family=DM+Mono:wght@400;500&family=Nunito:wght@400;500;600;700&display=swap%22 rel="stylesheet">
<style>

    :root {

      --bg:          #ffdbe6;

      --bg2:         #efe9e1;

      --surface:     #fdecf2;

      --surface2:    #faf7f4;

      --border:      #e8ddd4;

      --border2:     #d9cec3;

      --text:        #2d2520;

      --text2:       #5c4f46;

      --muted:       #9c8e85;

      --accent:      #c0846a;

      --accent-bg:   #f9ede8;

      --accent-bd:   #e8c4b5;

      --critical:    #b83232;

      --critical-bg: #fdecea;

      --critical-bd: #f0b8b5;

      --high:        #b05020;

      --high-bg:     #fef0e8;

      --high-bd:     #f0c8a8;

      --medium:      #BDB76B;

      --medium-bg:   #BDB76B;

      --medium-bd:   #BDB76B;

      --low:         #287048;

      --low-bg:      #eaf4ee;

      --low-bd:      #a8d8b8;

      --pass:        #287048;

      --pass-bg:     #eaf4ee;

      --fail:        #b83232;

      --fail-bg:     #fdecea;

      --regex-c:     #6848b0;

      --regex-bg:    #f0eaf9;

      --spacy-c:     #1870a0;

      --spacy-bg:    #e8f3f9;

      --llm-c:       #c0846a;

      --llm-bg:      #f9ede8;

      --display:     'Fraunces', Georgia, serif;

      --sans:        'Nunito', sans-serif;

      --mono:        'DM Mono', monospace;

      --shadow-sm:   0 1px 3px rgba(45,37,32,.06), 0 1px 2px rgba(45,37,32,.04);

      --shadow-md:   0 4px 16px rgba(45,37,32,.10), 0 2px 4px rgba(45,37,32,.04);

    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    html { scroll-behavior: smooth; }

    body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; font-size: 14px; line-height: 1.65; }
 
    /* Topbar */

    .topbar {

      position: sticky; top: 0; z-index: 100;

      background: rgba(247,244,240,.96); backdrop-filter: blur(10px);

      border-bottom: 1px solid var(--border);

      padding: 12px 32px;

      display: flex; align-items: center; justify-content: space-between;

    }

    .topbar-left  { display: flex; align-items: center; gap: 16px; }

    .topbar-right { display: flex; align-items: center; gap: 14px; }

    .logo { font-family: var(--display); font-size: 1.15rem; font-weight: 600; color: var(--accent); font-style: italic; }

    .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--low); animation: pulse 2.5s infinite; }

    @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.8)} }

    .topbar-tag { font-family: var(--mono); font-size: 0.67rem; padding: 3px 10px; border-radius: 20px; background: var(--accent-bg); color: var(--accent); border: 1px solid var(--accent-bd); }

    .topbar-status { font-family: var(--mono); font-size: 0.67rem; padding: 3px 10px; border-radius: 20px; background: var(--pass-bg); color: var(--pass); border: 1px solid var(--low-bd); }

    .topbar-ts { font-family: var(--mono); font-size: 0.67rem; color: var(--muted); }
 
    /* Layout */

    .shell { max-width: 1440px; margin: 0 auto; padding: 32px 32px 80px; }

    .section { margin-top: 40px; }

    .section-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }

    .section-head h2 { font-family: var(--display); font-size: 1.15rem; font-weight: 600; color: var(--text); }

    .section-head .pill { font-family: var(--mono); font-size: 0.64rem; padding: 2px 9px; border-radius: 20px; background: var(--bg2); color: var(--muted); border: 1px solid var(--border); }

    .divider { height: 1px; background: var(--border); margin-bottom: 20px; }
 
    /* Hero */

    .hero { display: grid; grid-template-columns: 196px 1fr; gap: 14px; margin-top: 24px; }

    .score-card {

      background: var(--surface); border: 1px solid var(--border);

      border-radius: 16px; box-shadow: var(--shadow-sm);

      padding: 28px 18px;

      display: flex; flex-direction: column; align-items: center; text-align: center;

    }

    .score-num { font-family: var(--display); font-size: 3.6rem; font-weight: 600; line-height: 1; letter-spacing: -2px; }

    .score-denom { font-family: var(--mono); font-size: 0.82rem; color: var(--muted); margin-top: 2px; }

    .score-risk { margin-top: 10px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; }

    .score-meta { margin-top: 12px; font-size: 0.68rem; color: var(--muted); line-height: 1.85; }

    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }

    .meta-card {

      background: var(--surface); border: 1px solid var(--border);

      border-radius: 14px; box-shadow: var(--shadow-sm);

      padding: 20px 22px; transition: box-shadow .2s, transform .2s;

    }

    .meta-card:hover { box-shadow: var(--shadow-md); transform: translateY(-2px); }

    .meta-card .num { font-family: var(--display); font-size: 2.5rem; font-weight: 600; line-height: 1; margin-bottom: 6px; letter-spacing: -1px; }

    .meta-card .lbl { font-size: 0.78rem; font-weight: 700; color: var(--text2); }

    .meta-card .sub { font-size: 0.67rem; color: var(--muted); margin-top: 3px; }
 
    /* Detection */

    .detect-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }

    .detect-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-sm); padding: 16px 18px; display: flex; align-items: center; gap: 14px; }

    .detect-icon { font-family: var(--mono); font-size: 0.7rem; font-weight: 500; padding: 6px 10px; border-radius: 8px; flex-shrink: 0; }

    .detect-icon.rx  { background: var(--regex-bg); color: var(--regex-c); }

    .detect-icon.nlp { background: var(--spacy-bg); color: var(--spacy-c); }

    .detect-icon.llm { background: var(--llm-bg);   color: var(--llm-c); }

    .detect-icon.evt { background: var(--bg2);      color: var(--muted); }

    .detect-num { font-family: var(--display); font-size: 1.8rem; font-weight: 600; line-height: 1; letter-spacing: -1px; }

    .detect-lbl { font-size: 0.68rem; color: var(--muted); margin-top: 2px; }
 
    /* Framework */

    .fw-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }

    .fw-card {

      background: var(--surface); border: 1px solid var(--border);

      border-radius: 14px; box-shadow: var(--shadow-sm);

      padding: 20px; cursor: pointer;

      transition: box-shadow .2s, transform .2s, border-color .2s;

    }

    .fw-card:hover  { box-shadow: var(--shadow-md); transform: translateY(-2px); }

    .fw-card.active { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-bg), var(--shadow-sm); }

    .fw-label { font-family: var(--mono); font-size: 0.67rem; font-weight: 500; color: var(--muted); letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 12px; }

    .fw-score-num { font-family: var(--display); font-size: 2.1rem; font-weight: 600; line-height: 1; letter-spacing: -1px; }

    .fw-status-badge { display: inline-block; margin-top: 7px; font-size: 0.63rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 3px 10px; border-radius: 20px; }

    .fw-status-badge.pass { background: var(--pass-bg); color: var(--pass); border: 1px solid var(--low-bd); }

    .fw-status-badge.fail { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--critical-bd); }

    .fw-bar-track { height: 3px; background: var(--bg2); border-radius: 2px; margin: 14px 0 10px; overflow: hidden; }

    .fw-bar-fill  { height: 100%; border-radius: 2px; transition: width .6s ease; }

    .fw-meta { font-size: 0.67rem; color: var(--muted); margin-bottom: 10px; }

    .fw-ctrl-row { display: flex; justify-content: space-between; align-items: center; font-size: 0.65rem; color: var(--text2); padding: 4px 0; border-bottom: 1px solid var(--border); }

    .fw-ctrl-row:last-child { border-bottom: none; }

    .fw-ctrl-id { font-family: var(--mono); font-size: 0.62rem; color: var(--muted); }
 
    /* Priority fixes */

    .pfix-list { display: flex; flex-direction: column; gap: 10px; }

    .pfix-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-sm); padding: 16px 20px; display: flex; gap: 14px; align-items: flex-start; }

    .pfix-rank { font-family: var(--display); font-size: 0.95rem; font-weight: 600; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px; }

    .pfix-title { font-size: 0.84rem; font-weight: 700; margin-bottom: 4px; color: var(--text); }

    .pfix-remed { font-size: 0.75rem; color: var(--text2); line-height: 1.65; }
 
    /* Filter */

    .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }

    .filter-btn { font-family: var(--sans); font-size: 0.76rem; font-weight: 600; padding: 5px 14px; border-radius: 20px; border: 1px solid var(--border2); background: var(--surface); color: var(--muted); cursor: pointer; transition: all .15s; }

    .filter-btn:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-bg); }

    .filter-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }

    .filter-sep { width: 1px; height: 18px; background: var(--border2); }
 
    /* Violations table */

    .vtable-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow-sm); overflow: hidden; }

    table { width: 100%; border-collapse: collapse; }

    thead th { background: var(--surface2); padding: 11px 16px; text-align: left; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); border-bottom: 1px solid var(--border); white-space: nowrap; }

    tbody tr.vrow { background: var(--surface); cursor: pointer; transition: background .1s; }

    tbody tr.vrow:hover { background: var(--surface2); }

    tbody tr.vrow td { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 0.81rem; vertical-align: middle; color: var(--text2); }

    tbody tr.vrow:last-of-type td { border-bottom: none; }

    .expand-row td { padding: 0; border-bottom: 1px solid var(--border); background: var(--bg); }

    .expand-inner { padding: 24px 28px; display: none; }

    .expand-inner.open { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }

    .expand-block h4 { font-size: 0.67rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); margin-bottom: 10px; }

    .expand-block p { font-size: 0.81rem; color: var(--text2); line-height: 1.78; }

    .matched-evidence { font-family: var(--mono); font-size: 0.7rem; background: var(--critical-bg); border: 1px solid var(--critical-bd); color: var(--critical); padding: 9px 12px; border-radius: 8px; margin-top: 12px; word-break: break-all; }

    .ctrl-chips { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 12px; }

    .ctrl-chip { font-family: var(--mono); font-size: 0.61rem; padding: 3px 9px; border-radius: 20px; background: var(--bg2); color: var(--text2); border: 1px solid var(--border2); }

    .fw-chip { font-family: var(--mono); font-size: 0.61rem; font-weight: 500; padding: 3px 9px; border-radius: 20px; background: var(--accent-bg); color: var(--accent); border: 1px solid var(--accent-bd); }

    .meta-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }

    .meta-pill { font-size: 0.67rem; color: var(--muted); font-family: var(--mono); }

    .chevron { color: var(--border2); font-size: 0.65rem; transition: transform .2s; }

    .chevron.open { transform: rotate(180deg); color: var(--accent); }
 
    /* Severity badges */

    .sev { font-family: var(--mono); font-size: 0.62rem; font-weight: 700; padding: 3px 9px; border-radius: 20px; letter-spacing: .4px; white-space: nowrap; }

    .sev-CRITICAL { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-bd); }

    .sev-HIGH     { background: var(--high-bg);     color: var(--high);     border: 1px solid var(--high-bd); }

    .sev-MEDIUM   { background: var(--medium-bg);   color: var(--medium);   border: 1px solid var(--medium-bd); }

    .sev-LOW      { background: var(--low-bg);      color: var(--low);      border: 1px solid var(--low-bd); }
 
    /* Detector badges */

    .det-badge { font-family: var(--mono); font-size: 0.6rem; font-weight: 600; padding: 2px 8px; border-radius: 20px; }

    .det-REGEX { background: var(--regex-bg); color: var(--regex-c); border: 1px solid #d0c0f0; }

    .det-SPACY { background: var(--spacy-bg); color: var(--spacy-c); border: 1px solid #b0d8f0; }

    .det-LLM   { background: var(--llm-bg);   color: var(--llm-c);   border: 1px solid var(--accent-bd); }
 
    /* Events */

    .event-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow-sm); overflow: hidden; }

    tbody tr.erow td { padding: 11px 16px; border-bottom: 1px solid var(--border); font-size: 0.8rem; color: var(--text2); }

    tbody tr.erow:last-child td { border-bottom: none; }

    tbody tr.erow:hover { background: var(--surface2); }

    .evt-type { font-family: var(--mono); font-size: 0.64rem; font-weight: 600; padding: 2px 9px; border-radius: 20px; background: var(--accent-bg); color: var(--accent); border: 1px solid var(--accent-bd); }

    .evt-sha { font-family: var(--mono); font-size: 0.67rem; color: var(--muted); }
 
    /* Health */

    .health-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }

    .health-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow-sm); padding: 16px 18px; }

    .health-lbl { font-size: 0.66rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 7px; }

    .health-val { font-family: var(--mono); font-size: 0.87rem; font-weight: 500; }

    .h-ok   { color: var(--low); }

    .h-warn { color: var(--medium); }

    .h-fail { color: var(--critical); }
 
    /* Empty */

    .empty { padding: 40px 20px; text-align: center; color: var(--muted); font-size: 0.81rem; }

    .empty-icon { font-size: 1.8rem; margin-bottom: 8px; opacity: .3; }
 
    /* Footer */

    .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; font-family: var(--mono); font-size: 0.67rem; color: var(--muted); }
 
    ::-webkit-scrollbar { width: 5px; }

    ::-webkit-scrollbar-track { background: var(--bg); }

    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
</style>
</head>
<body>
 
<div class="topbar">
<div class="topbar-left">
<span class="logo">avirat.ai</span>
<span class="live-dot"></span>
<span class="topbar-tag">Compliance Monitor</span>
</div>
<div class="topbar-right">
<span class="topbar-ts">{{ generated_at }}</span>
<span class="topbar-status">{{ pipeline_status }}</span>
</div>
</div>
 
<div class="shell">
 
  <!-- Hero -->
<div class="hero">
<div class="score-card">
<div class="score-num" style="color:{{ score_color }}">{{ overall_score }}</div>
<div class="score-denom">/100</div>
<div class="score-risk" style="color:{{ score_color }}">{{ risk_level }}</div>
<div class="score-meta">Last scan: {{ last_scan }}<br>{{ total_violations }} violation{{ 's' if total_violations != 1 else '' }}</div>
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
 
  <!-- Detection engine -->
<div class="section">
<div class="section-head"><h2>Detection Engine</h2></div>
<div class="divider"></div>
<div class="detect-grid">
<div class="detect-card">
<div class="detect-icon rx">RX</div>
<div>
<div class="detect-num" style="color:var(--regex-c)">{{ regex_detections }}</div>
<div class="detect-lbl">Regex (structural)</div>
</div>
</div>
<div class="detect-card">
<div class="detect-icon nlp">NLP</div>
<div>
<div class="detect-num" style="color:var(--spacy-c)">{{ spacy_detections }}</div>
<div class="detect-lbl">spaCy (NLP + NER)</div>
</div>
</div>
<div class="detect-card">
<div class="detect-icon llm">LLM</div>
<div>
<div class="detect-num" style="color:var(--llm-c)">{{ llm_detections }}</div>
<div class="detect-lbl">LLM enrichments</div>
</div>
</div>
<div class="detect-card">
<div class="detect-icon evt">EVT</div>
<div>
<div class="detect-num" style="color:var(--text)">{{ event_count }}</div>
<div class="detect-lbl">Events scanned</div>
</div>
</div>
</div>
</div>
 
  <!-- Framework compliance -->
<div class="section">
<div class="section-head"><h2>Framework Compliance</h2></div>
<div class="divider"></div>
<div class="fw-grid">

      {% for fw, data in frameworks.items() %}
<div class="fw-card" id="fw-{{ fw }}" onclick="filterByFramework('{{ fw }}')">
<div class="fw-label">{{ fw }}</div>
<div class="fw-score-num" style="color:{{ data.color }}">{{ data.score }}<span style="font-size:0.95rem;color:var(--muted);font-weight:400">/100</span></div>
<div><span class="fw-status-badge {{ 'pass' if data.status == 'PASS' else 'fail' }}">{{ data.status }}</span></div>
<div class="fw-bar-track"><div class="fw-bar-fill" style="width:{{ data.score }}%;background:{{ data.color }}"></div></div>
<div class="fw-meta">{{ data.violations }} violation{{ 's' if data.violations != 1 else '' }} &nbsp;·&nbsp; {{ data.controls_hit }} control{{ 's' if data.controls_hit != 1 else '' }}</div>

        {% if data.controls %}

          {% for ctrl in data.controls[:4] %}
<div class="fw-ctrl-row">
<span class="fw-ctrl-id">{{ ctrl.id }}</span>
<span class="sev sev-{{ ctrl.severity }}">{{ ctrl.severity }}</span>
</div>

          {% endfor %}

          {% if data.controls|length > 4 %}
<div style="font-size:0.61rem;color:var(--muted);padding-top:4px">+{{ data.controls|length - 4 }} more</div>

          {% endif %}

        {% else %}
<div style="font-size:0.7rem;color:var(--low);margin-top:4px">✓ All controls passing</div>

        {% endif %}
</div>

      {% endfor %}
</div>
</div>
 
  <!-- Priority fixes -->

  {% if priority_fixes %}
<div class="section">
<div class="section-head">
<h2>Priority Remediation</h2>
<span class="pill">Top {{ [priority_fixes|length, 5]|min }}</span>
</div>
<div class="divider"></div>
<div class="pfix-list">

      {% for fix in priority_fixes[:5] %}
<div class="pfix-card">
<div class="pfix-rank" style="background:{{ {'CRITICAL':'var(--critical-bg)','HIGH':'var(--high-bg)','MEDIUM':'var(--medium-bg)','LOW':'var(--low-bg)'}.get(fix.severity,'var(--bg2)') }};color:{{ {'CRITICAL':'var(--critical)','HIGH':'var(--high)','MEDIUM':'var(--medium)','LOW':'var(--low)'}.get(fix.severity,'var(--muted)') }}">{{ fix.rank }}</div>
<div style="padding-top:2px"><span class="sev sev-{{ fix.severity }}">{{ fix.severity }}</span></div>
<div>
<div class="pfix-title">{{ fix.title }}</div>
<div class="pfix-remed">{{ fix.remediation }}</div>
</div>
</div>

      {% endfor %}
</div>
</div>

  {% endif %}
 
  <!-- Active violations -->
<div class="section">
<div class="section-head">
<h2>Active Violations</h2>
<span class="pill">{{ total_violations }}</span>
</div>
<div class="divider"></div>
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
<tr><th>Severity</th><th>ID</th><th>Title</th><th>Rule</th><th>Detector</th><th>User</th><th>Frameworks</th><th>Detected</th><th></th></tr>
</thead>
<tbody id="vtbody">

          {% if violations %}

            {% for v in violations %}
<tr class="vrow" data-sev="{{ v.severity }}" data-det="{{ v.get('detection','LLM') }}" onclick="toggleV('{{ v.id }}')">
<td><span class="sev sev-{{ v.severity }}">{{ v.severity }}</span></td>
<td><span style="font-family:var(--mono);font-size:0.69rem;color:var(--muted)">{{ v.id }}</span></td>
<td style="font-weight:700;max-width:260px;color:var(--text)">{{ v.title }}</td>
<td><span style="font-family:var(--mono);font-size:0.65rem;color:var(--muted)">{{ v.get('rule_id','—') }}</span></td>
<td><span class="det-badge det-{{ v.get('detection','LLM') }}">{{ v.get('detection','LLM') }}</span></td>
<td style="font-family:var(--mono);font-size:0.69rem">{{ v.get('user_involved','—') }}</td>
<td><div style="display:flex;gap:4px;flex-wrap:wrap">{% for fw in v.get('frameworks',{}).keys() %}<span class="fw-chip">{{ fw }}</span>{% endfor %}</div></td>
<td style="font-family:var(--mono);font-size:0.65rem;color:var(--muted);white-space:nowrap">{{ v.get('timestamp','—')[:16] }}</td>
<td><span class="chevron" id="chev-{{ v.id }}">▾</span></td>
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

                        {% if ctrl and ctrl != 'null' %}<span class="ctrl-chip">{{ fw }}: {{ ctrl }}</span>{% endif %}

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
<span class="pill">{{ github_events|length }}</span>
</div>
<div class="divider"></div>
<div class="event-wrap">
<table>
<thead>
<tr><th>Event</th><th>Action</th><th>Repository</th><th>User</th><th>Ref / PR</th><th>Commits</th><th>Received</th></tr>
</thead>
<tbody>

          {% if github_events %}

            {% for e in github_events %}
<tr class="erow">
<td><span class="evt-type">{{ e.event_type }}</span></td>
<td style="color:var(--muted)">{{ e.action }}</td>
<td style="font-family:var(--mono);font-size:0.7rem">{{ e.repo }}</td>
<td style="font-family:var(--mono);font-size:0.7rem;color:var(--accent)">{{ e.user }}</td>
<td><span class="evt-sha">{{ e.ref }}</span></td>
<td style="font-family:var(--mono);font-size:0.68rem;color:var(--muted)">{{ e.commits }}</td>
<td style="font-family:var(--mono);font-size:0.67rem;color:var(--muted)">{{ e.received_at }}</td>
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
<div class="divider"></div>
<div class="health-grid">
<div class="health-card">
<div class="health-lbl">Layer 1 — Scan</div>
<div class="health-val {{ 'h-ok' if health.layer1 else 'h-fail' }}">{{ '✓ OK' if health.layer1 else '✗ No data' }}</div>
</div>
<div class="health-card">
<div class="health-lbl">Layer 2 — Framework</div>
<div class="health-val {{ 'h-ok' if health.layer2 else 'h-fail' }}">{{ '✓ OK' if health.layer2 else '✗ No data' }}</div>
</div>
<div class="health-card">
<div class="health-lbl">Webhook Data</div>
<div class="health-val {{ 'h-ok' if health.webhook else 'h-warn' }}">{{ '✓ Receiving' if health.webhook else '⚠ None yet' }}</div>
</div>
<div class="health-card">
<div class="health-lbl">Last Scan Age</div>
<div class="health-val {{ 'h-ok' if health.fresh else 'h-warn' }}">{{ health.scan_age }}</div>
</div>
<div class="health-card">
<div class="health-lbl">Frameworks Passing</div>
<div class="health-val h-ok">{{ health.passing_fw }}/4</div>
</div>
</div>
</div>
 
  <div class="footer">

    avirat.ai &nbsp;·&nbsp; azure openai gpt-4o &nbsp;·&nbsp;

    iso27001 &nbsp;·&nbsp; soc2 &nbsp;·&nbsp; hipaa &nbsp;·&nbsp; gdpr &nbsp;·&nbsp;

    refreshes every 30s &nbsp;·&nbsp; {{ generated_at }}
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

    const show  = testFn(row);

    const match = (row.getAttribute('onclick') || '').match(/'([^']+)'/);

    const vid   = match ? match[1] : null;

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

SEV_COLORS = {

    "CRITICAL": "#b83232",

    "HIGH":     "#b05020",

    "MEDIUM":   "#902245",

    "LOW":      "#287048",

}

SEV_RGB = {

    "CRITICAL": "184,50,50",

    "HIGH":     "176,80,32",

    "MEDIUM":   "144,112,24",

    "LOW":      "40,112,72",

}
 
 
def score_color(s: int) -> str:

    if s < 60: return "#b83232"

    if s < 75: return "#b05020"

    if s < 90: return "#902245"

    return "#287048"
 
 
def risk_level(s: int) -> str:

    if s < 60: return "Critical Risk"

    if s < 75: return "High Risk"

    if s < 90: return "Medium Risk"

    return "Passing"
 
 
def scan_age(generated_at_iso: str) -> tuple[str, bool]:

    try:

        delta = (datetime.utcnow() - datetime.fromisoformat(generated_at_iso)).total_seconds()

        if delta < 60:   return "< 1 min ago", True

        if delta < 3600: return f"{int(delta//60)} min ago", True

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

        color  = "#287048" if status == "PASS" else "#b83232"

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

    violations      = []

    summary         = {}

    frameworks      = {}

    overall_score   = 100

    priority_fixes  = []

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

            frameworks[fw] = {"score":100,"violations":0,"controls_hit":0,"status":"PASS","color":"#287048","controls":[]}
 
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
 