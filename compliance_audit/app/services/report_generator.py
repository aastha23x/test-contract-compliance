import json
import os
from datetime import datetime

# ── Absolute path anchors ─────────────────────────────────────
# app/services/report_generator.py → up two levels to project root
ROOT          = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VIOLATION_IN  = os.path.join(ROOT, "violation_report.json")
FRAMEWORK_IN  = os.path.join(ROOT, "framework_mapping_report.json")
DASHBOARD_OUT = os.path.join(ROOT, "compliance_dashboard.html")

SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
SEV_BG    = {"CRITICAL": "rgba(239,68,68,0.15)", "HIGH": "rgba(249,115,22,0.15)",
             "MEDIUM": "rgba(234,179,8,0.15)", "LOW": "rgba(34,197,94,0.15)"}


def score_color(s):
    return "#ef4444" if s < 60 else "#f97316" if s < 75 else "#eab308" if s < 90 else "#22c55e"


def score_label(s):
    return "CRITICAL" if s < 60 else "HIGH" if s < 75 else "MEDIUM" if s < 90 else "PASSING"


def load_reports():
    if not os.path.exists(VIOLATION_IN):
        print(f"❌ violation_report.json not found at {VIOLATION_IN}")
        print("   Run Layer 1 (compliance_agent.py) first.")
        raise SystemExit(1)

    with open(VIOLATION_IN) as f:
        vr = json.load(f)

    fr = {}
    if os.path.exists(FRAMEWORK_IN):
        with open(FRAMEWORK_IN) as f:
            fr = json.load(f)
    else:
        print(f"⚠️  framework_mapping_report.json not found at {FRAMEWORK_IN} — scores will default to 100.")

    return vr, fr


def generate_report():
    print("Generating HTML Compliance Dashboard...")
    vr, fr = load_reports()
    violations = vr.get("violations", [])
    summary    = vr.get("summary", {})
    fw_scores  = fr.get("framework_scores", {})
    fw_map     = fr.get("framework_map", {})
    gen_at     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        score_num = int(str(fr.get("overall_score", summary.get("compliance_score", 0))).replace("/100", "").strip())
    except (ValueError, AttributeError):
        score_num = 0

    ring_color = score_color(score_num)
    ring_dash  = int(score_num * 2.51)
    sev_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_v   = sorted(violations, key=lambda x: sev_order.get(x.get("severity", "LOW"), 3))

    # violation rows
    rows = ""
    for v in sorted_v:
        sev = v.get("severity", "LOW")
        c   = SEV_COLOR.get(sev, "#888")
        bg  = SEV_BG.get(sev, "rgba(0,0,0,.1)")
        fws = " ".join(
            f'<span onclick="filterByFramework(\'{fw}\'); event.stopPropagation();" style="background:#e0e7ff;color:#4338ca;padding:3px 8px;border-radius:4px;font-size:.65rem;font-weight:700;cursor:pointer;transition:all 0.2s" onmouseover="this.style.background=\'#c7d2fe\'" onmouseout="this.style.background=\'#e0e7ff\'" title="Click to filter by {fw}">{fw}</span>'
            for fw, ctrl in v.get("frameworks", {}).items() if ctrl and ctrl != "null"
        )
        rows += f"""<tr class="vr" data-s="{sev}" onclick="toggleRow('{v.get('id','')}')" style="cursor:pointer">
          <td><span style="background:{bg};color:{c};padding:4px 12px;border-radius:999px;font-size:.7rem;font-weight:600;letter-spacing:0.5px">{sev}</span></td>
          <td style="font-weight:600;font-family:monospace;color:#475569">{v.get('id','')}</td>
          <td style="font-weight:500;max-width:250px;color:#1e293b">{v.get('title','')}</td>
          <td style="color:#475569">{v.get('source','')}</td>
          <td style="font-size:.75rem;color:#64748b">{v.get('user_involved','N/A')}</td>
          <td style="display:flex;gap:4px;flex-wrap:wrap;align-items:center;min-height:48px">{fws}</td>
          <td style="text-align:right;color:#94a3b8;font-size:.7rem">CLICK TO EXPAND ▼</td>
        </tr>
        <tr id="desc-{v.get('id','')}" style="display:none;background:#f8fafc">
          <td colspan="7" style="padding:20px 24px;border-top:1px solid #e2e8f0">
            <h2 style="font-size:1.1rem;color:#0f172a;margin-bottom:16px;font-weight:600">Framework Readiness</h2>
            <div style="font-size:.85rem;color:#334155;margin-bottom:16px;line-height:1.6">
              <strong style="color:#0f172a;font-size:0.9rem">Detailed Explanation:</strong><br>{v.get('description','')}
            </div>
            <div style="font-size:.85rem;color:#334155;line-height:1.6">
              <strong style="color:#0f172a;font-size:0.9rem">Remediation Steps:</strong><br>{v.get('remediation','')}
            </div>
          </td>
        </tr>"""

    # framework cards
    fw_cards = ""
    for fw in ["ISO27001", "SOC2", "HIPAA", "GDPR"]:
        sc    = fw_scores.get(fw, 100)
        viols = sum(len(v) for v in fw_map.get(fw, {}).values())
        fw_cards += f"""<div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:24px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05)">
          <div style="font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:12px;font-weight:600">{fw} Readiness</div>
          <div style="display:flex;justify-content:space-between;align-items:flex-end">
            <div>
              <div class="card-value" style="font-size:2rem;font-weight:700;color:#0f172a">{viols}</div>
              <div style="font-size:.75rem;color:#64748b;margin-top:4px">Violations mapped</div>
            </div>
            <div style="width:50%;height:6px;background:#f1f5f9;border-radius:999px;overflow:hidden">
              <div style="height:100%;width:{min(100, viols*15)}%;background:{'#ef4444' if viols>0 else '#10b981'}"></div>
            </div>
          </div>
        </div>"""

    # priority items
    prio = ""
    for i, v in enumerate(sorted_v[:5], 1):
        sev = v.get("severity", "LOW")
        c   = SEV_COLOR.get(sev, "#888")
        prio += f"""<div style="display:flex;align-items:flex-start;gap:12px;padding:14px 0;border-bottom:1px solid #e2e8f0">
          <div style="width:28px;height:28px;border-radius:50%;background:{SEV_BG.get(sev)};color:{c};display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:800;flex-shrink:0;margin-top:2px">{i}</div>
          <div style="flex:1;min-width:0">
            <div style="font-size:.82rem;font-weight:600;color:#0f172a">{v.get('title','')}</div>
            <div style="font-size:.72rem;color:#64748b;margin-top:4px;line-height:1.4">{v.get('remediation','')}</div>
          </div>
          <span style="background:{SEV_BG.get(sev)};color:{c};padding:3px 10px;border-radius:999px;font-size:.7rem;font-weight:700;flex-shrink:0">{sev}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Audit Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Plus Jakarta Sans',sans-serif;background:#f8fafc;color:#334155;min-height:100vh;padding-bottom:60px}}
h1, h2, h3, .card-value {{font-family:'Outfit',sans-serif}}
table{{width:100%;border-collapse:collapse}}
th{{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#64748b;padding:16px;text-align:left;border-bottom:1px solid #e2e8f0;white-space:nowrap;background:#f1f5f9}}
td{{padding:16px;font-size:.85rem;border-bottom:1px solid #e2e8f0;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
.vr{{transition:background .2s;background:#ffffff}}.vr:hover{{background:#f1f5f9}}
.fbtn{{padding:6px 16px;border-radius:999px;border:1px solid #cbd5e1;background:#ffffff;color:#475569;font-size:.75rem;font-weight:600;cursor:pointer;transition:all .2s;font-family:'Plus Jakarta Sans',sans-serif}}
.fbtn:hover,.fbtn.active{{background:#3b82f6;border-color:#3b82f6;color:#ffffff}}
</style>
</head>
<body>
<div style="max-width:1400px;margin:0 auto;padding:40px 24px">
  <header style="margin-bottom:40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e2e8f0;padding-bottom:24px">
    <div>
      <h1 style="font-size:2rem;color:#0f172a;margin-bottom:8px">Compliance Audit Dashboard</h1>
      <p style="color:#64748b;font-size:.85rem">Generated by Compliance Agent • {gen_at}</p>
    </div>
    <div style="background:#e0e7ff;color:#4338ca;padding:6px 16px;border-radius:999px;font-size:.75rem;font-weight:600;border:1px solid #c7d2fe">
      AI-Powered Analysis
    </div>
  </header>

  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:32px">
    {"".join(f'''<div onclick="filterTable('{lbl.upper()}')" style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:20px 24px;border-top:3px solid {clr};box-shadow:0 1px 3px rgba(0,0,0,0.05);cursor:pointer;transition:all 0.2s" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 4px 12px rgba(0,0,0,0.08)'" onmouseout="this.style.transform='';this.style.boxShadow='0 1px 3px rgba(0,0,0,0.05)'">
      <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748b">Click to view {lbl}</div>
      <div style="font-size:2.2rem;font-weight:800;color:#0f172a;margin-top:8px;line-height:1">{val}</div>
      <div style="font-size:.75rem;color:#64748b;margin-top:6px">Violations</div>
    </div>''' for lbl, val, clr in [
        ("Critical", summary.get("critical",0), "#ef4444"),
        ("High",     summary.get("high",0),     "#f97316"),
        ("Medium",   summary.get("medium",0),   "#eab308"),
        ("Low",      summary.get("low",0),       "#22c55e"),
        ("Total",    summary.get("total_violations",0), "#6366f1"),
    ])}
  </div>

  <div style="display:grid;grid-template-columns:1fr 320px;gap:24px;margin-bottom:32px">
    <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05)">
      <div style="padding:20px 24px 16px;border-bottom:1px solid #e2e8f0">
        <div style="font-size:.9rem;font-weight:700;color:#0f172a">Top Priority Fixes</div>
      </div>
      <div style="padding:0 24px 24px">{prio}</div>
    </div>

    <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;display:flex;flex-direction:column;align-items:center;padding:32px 24px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05)">
      <div style="font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px">Overall Score</div>
      <div style="position:relative;display:flex;align-items:center;justify-content:center">
        <svg width="160" height="160" viewBox="0 0 100 100" style="transform:rotate(-90deg)">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#e2e8f0" stroke-width="10"/>
          <circle cx="50" cy="50" r="40" fill="none" stroke="{ring_color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="{ring_dash} 251"/>
        </svg>
        <div style="position:absolute;text-align:center">
          <div style="font-size:2.4rem;font-weight:800;color:#0f172a;line-height:1">{score_num}</div>
          <div style="font-size:.7rem;color:#64748b">/100</div>
        </div>
      </div>
      <div style="margin-top:20px;text-align:center">
        <div style="font-size:1rem;font-weight:700;color:{ring_color}">{score_label(score_num)}</div>
      </div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px">
    {fw_cards}
  </div>

  <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);overflow:hidden">
    <div style="padding:24px;border-bottom:1px solid #e2e8f0">
      <h2 style="font-size:1.1rem;color:#0f172a;margin-bottom:4px;font-weight:600">All Detected Violations</h2>
      <p style="font-size:.8rem;color:#64748b;margin-bottom:20px">Sorted by severity · Click a row to view details</p>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button id="btn-all" class="fbtn active" onclick="filterTable('all')">All ({len(violations)})</button>
        <button id="btn-CRITICAL" class="fbtn" onclick="filterTable('CRITICAL')">Critical ({summary.get('critical',0)})</button>
        <button id="btn-HIGH" class="fbtn" onclick="filterTable('HIGH')">High ({summary.get('high',0)})</button>
        <button id="btn-MEDIUM" class="fbtn" onclick="filterTable('MEDIUM')">Medium ({summary.get('medium',0)})</button>
        <button id="btn-LOW" class="fbtn" onclick="filterTable('LOW')">Low ({summary.get('low',0)})</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr>
          <th>Severity</th><th>ID</th><th>Title</th><th>Source</th><th>User</th><th>Frameworks</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>

  <div style="text-align:center;color:#64748b;font-size:.72rem;padding-top:24px;border-top:1px solid rgba(255,255,255,.07)">
    Avirat.ai Compliance Agent &nbsp;·&nbsp; Azure OpenAI GPT-4o &nbsp;·&nbsp; ISO27001 · SOC2 · HIPAA · GDPR &nbsp;·&nbsp; {gen_at}
  </div>
</div>

<script>
function filterTable(s) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + s).classList.add('active');
  document.querySelectorAll('.vr').forEach(r => {{
    r.style.display = (s === 'all' || r.dataset.s === s) ? '' : 'none';
    let desc = document.getElementById('desc-' + r.children[1].innerText);
    if(desc) desc.style.display = 'none';
  }});
}}
function filterByFramework(fw) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.vr').forEach(r => {{
    let frameworksText = r.children[5].innerText;
    r.style.display = frameworksText.includes(fw) ? '' : 'none';
    let desc = document.getElementById('desc-' + r.children[1].innerText);
    if(desc) desc.style.display = 'none';
  }});
}}
function toggleRow(id) {{
  let el = document.getElementById('desc-' + id);
  el.style.display = el.style.display === 'none' ? '' : 'none';
}}
</script>
</body></html>"""

    with open(DASHBOARD_OUT, "w") as f:
        f.write(html)
    print(f"📄 Dashboard saved to:  {DASHBOARD_OUT}")
    print(f"   Open in browser:    file://{DASHBOARD_OUT}")
    return DASHBOARD_OUT


if __name__ == "__main__":
    generate_report()