"""
SOC Automation Dashboard
Reads processed alert data and displays a real-time dashboard.
"""
from flask import Flask, render_template_string, jsonify
import json
import os
from collections import defaultdict

app = Flask(__name__)

REPORTS_DIR = "reports"
ALERT_LOG_FILE = "alert_log.json"

def load_alert_log():
    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def get_stats(alerts):
    total = len(alerts)
    severity_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    mitre_counts = defaultdict(int)
    fp_scores = []
    alerts_over_time = defaultdict(int)
    verdicts = defaultdict(int)

    for a in alerts:
        severity_counts[a.get("severity", "unknown").lower()] += 1
        ip = a.get("source_ip", "unknown")
        if ip != "unknown":
            ip_counts[ip] += 1
        mitre = a.get("mitre_technique", "Unknown")
        if mitre and mitre != "Unknown":
            mitre_counts[mitre] += 1
        score = a.get("fp_score")
        if score is not None:
            fp_scores.append(score)
        verdict = a.get("fp_verdict", "UNKNOWN")
        verdicts[verdict] += 1
        ts = a.get("timestamp", "")
        if ts and len(ts) >= 10:
            alerts_over_time[ts[:10]] += 1

    avg_fp = round(sum(fp_scores) / len(fp_scores), 1) if fp_scores else 0
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_mitre = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:6]
    sorted_dates = sorted(alerts_over_time.items())

    buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for s in fp_scores:
        if s <= 20: buckets["0-20"] += 1
        elif s <= 40: buckets["21-40"] += 1
        elif s <= 60: buckets["41-60"] += 1
        elif s <= 80: buckets["61-80"] += 1
        else: buckets["81-100"] += 1

    return {
        "total": total,
        "severity": dict(severity_counts),
        "top_ips": top_ips,
        "top_mitre": top_mitre,
        "avg_fp_score": avg_fp,
        "fp_buckets": buckets,
        "verdicts": dict(verdicts),
        "alerts_over_time": sorted_dates,
        "report_count": len([f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]) if os.path.exists(REPORTS_DIR) else 0,
    }

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Automation Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{--bg:#080c10;--bg2:#0d1117;--bg3:#111820;--border:#1e3a4a;--accent:#00d4ff;--accent2:#00ff9d;--accent3:#ff4d6d;--accent4:#ffd166;--text:#c9d8e8;--text-dim:#4a6a7a;--critical:#ff4d6d;--high:#ff8c42;--medium:#ffd166;--low:#00ff9d;--glow:0 0 20px rgba(0,212,255,0.3)}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:15px;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:radial-gradient(ellipse at 10% 20%,rgba(0,212,255,0.04) 0%,transparent 50%),radial-gradient(ellipse at 90% 80%,rgba(0,255,157,0.03) 0%,transparent 50%);pointer-events:none;z-index:0}
body::after{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.05) 2px,rgba(0,0,0,0.05) 4px);pointer-events:none;z-index:0}
.container{max-width:1400px;margin:0 auto;padding:0 24px 40px;position:relative;z-index:1}
header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);margin-bottom:28px;position:relative;z-index:1}
.logo{display:flex;align-items:center;gap:14px}
.logo-icon{width:42px;height:42px;border:2px solid var(--accent);display:flex;align-items:center;justify-content:center;font-family:'Share Tech Mono',monospace;font-size:18px;color:var(--accent);box-shadow:var(--glow),inset 0 0 10px rgba(0,212,255,0.1);animation:pulse-border 3s ease-in-out infinite}
@keyframes pulse-border{0%,100%{box-shadow:var(--glow),inset 0 0 10px rgba(0,212,255,0.1)}50%{box-shadow:0 0 30px rgba(0,212,255,0.5),inset 0 0 15px rgba(0,212,255,0.2)}}
.logo-text h1{font-size:20px;font-weight:700;letter-spacing:3px;color:#fff;text-transform:uppercase}
.logo-text p{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:2px}
.header-right{display:flex;align-items:center;gap:20px}
.live-indicator{display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--accent2);letter-spacing:1px}
.live-dot{width:8px;height:8px;background:var(--accent2);border-radius:50%;animation:blink 1.5s ease-in-out infinite;box-shadow:0 0 8px var(--accent2)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
.timestamp{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--text-dim)}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:var(--bg2);border:1px solid var(--border);padding:20px 24px;position:relative;overflow:hidden;transition:border-color 0.3s;animation:fadeInUp 0.5s ease both}
.stat-card:nth-child(1){animation-delay:0.1s}.stat-card:nth-child(2){animation-delay:0.2s}.stat-card:nth-child(3){animation-delay:0.3s}.stat-card:nth-child(4){animation-delay:0.4s}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--card-accent,var(--accent))}
.stat-card:hover{border-color:var(--accent)}
.stat-label{font-size:11px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase;margin-bottom:10px;font-family:'Share Tech Mono',monospace}
.stat-value{font-size:42px;font-weight:700;color:var(--card-accent,var(--accent));line-height:1;margin-bottom:6px}
.stat-sub{font-size:12px;color:var(--text-dim);font-family:'Share Tech Mono',monospace}
.stat-card .corner{position:absolute;bottom:12px;right:16px;font-size:32px;opacity:0.06;font-family:'Share Tech Mono',monospace;color:var(--card-accent,var(--accent))}
.charts-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.chart-card{background:var(--bg2);border:1px solid var(--border);padding:20px 24px;animation:fadeInUp 0.5s ease both}
.chart-title{font-size:11px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase;font-family:'Share Tech Mono',monospace;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.chart-title::before{content:'';width:3px;height:12px;background:var(--accent);display:inline-block}
.chart-container{position:relative;height:200px}
.ip-table{width:100%;border-collapse:collapse}
.ip-table tr{border-bottom:1px solid rgba(30,58,74,0.5);transition:background 0.2s}
.ip-table tr:hover{background:rgba(0,212,255,0.03)}
.ip-table tr:last-child{border-bottom:none}
.ip-table td{padding:10px 4px;font-family:'Share Tech Mono',monospace;font-size:12px}
.ip-table td:first-child{color:var(--accent)}
.ip-table td:last-child{text-align:right;color:var(--text-dim)}
.ip-bar-wrap{padding:0 12px}
.ip-bar{height:4px;background:rgba(0,212,255,0.15);border-radius:2px;overflow:hidden}
.ip-bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:2px}
.verdict-grid{display:flex;flex-direction:column;gap:10px;margin-top:8px}
.verdict-row{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border:1px solid var(--border);background:var(--bg3)}
.verdict-label{font-size:11px;letter-spacing:1px;font-family:'Share Tech Mono',monospace}
.verdict-count{font-size:22px;font-weight:700}
.verdict-tp{border-left:3px solid var(--critical)}.verdict-tp .verdict-count{color:var(--critical)}
.verdict-uncertain{border-left:3px solid var(--accent4)}.verdict-uncertain .verdict-count{color:var(--accent4)}
.verdict-fp{border-left:3px solid var(--accent2)}.verdict-fp .verdict-count{color:var(--accent2)}
.alerts-table-wrap{overflow-x:auto}
.alerts-table{width:100%;border-collapse:collapse;font-size:13px}
.alerts-table th{text-align:left;padding:10px 12px;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase;border-bottom:1px solid var(--border)}
.alerts-table td{padding:10px 12px;border-bottom:1px solid rgba(30,58,74,0.4);font-family:'Share Tech Mono',monospace;font-size:11px}
.alerts-table tr:hover td{background:rgba(0,212,255,0.02)}
.badge{display:inline-block;padding:2px 8px;font-size:10px;letter-spacing:1px;font-weight:700;text-transform:uppercase}
.badge-critical{background:rgba(255,77,109,0.15);color:var(--critical);border:1px solid rgba(255,77,109,0.3)}
.badge-high{background:rgba(255,140,66,0.15);color:var(--high);border:1px solid rgba(255,140,66,0.3)}
.badge-medium{background:rgba(255,209,102,0.15);color:var(--accent4);border:1px solid rgba(255,209,102,0.3)}
.badge-low{background:rgba(0,255,157,0.1);color:var(--accent2);border:1px solid rgba(0,255,157,0.2)}
.badge-unknown{background:rgba(74,106,122,0.2);color:var(--text-dim);border:1px solid var(--border)}
.score-pill{display:inline-block;padding:2px 8px;font-size:10px;font-family:'Share Tech Mono',monospace;font-weight:700}
.score-high{background:rgba(255,77,109,0.15);color:var(--critical)}
.score-mid{background:rgba(255,209,102,0.15);color:var(--accent4)}
.score-low{background:rgba(0,255,157,0.1);color:var(--accent2)}
.no-data{text-align:center;padding:40px;color:var(--text-dim);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px}
footer{text-align:center;padding:20px;border-top:1px solid var(--border);font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim);letter-spacing:2px;margin-top:20px;position:relative;z-index:1}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">&#11041;</div>
    <div class="logo-text">
      <h1>SOC Command Center</h1>
      <p>// AI-POWERED THREAT INTELLIGENCE PIPELINE</p>
    </div>
  </div>
  <div class="header-right">
    <div class="live-indicator"><div class="live-dot"></div>PIPELINE ACTIVE</div>
    <div class="timestamp" id="clock"></div>
  </div>
</header>
<div class="container">
  <div class="stat-grid">
    <div class="stat-card" style="--card-accent:var(--accent)">
      <div class="stat-label">Alerts Processed</div>
      <div class="stat-value">{{ stats.total }}</div>
      <div class="stat-sub">total incidents triaged</div>
      <div class="corner">ALT</div>
    </div>
    <div class="stat-card" style="--card-accent:var(--accent2)">
      <div class="stat-label">Reports Generated</div>
      <div class="stat-value">{{ stats.report_count }}</div>
      <div class="stat-sub">pdf incident reports</div>
      <div class="corner">RPT</div>
    </div>
    <div class="stat-card" style="--card-accent:var(--accent3)">
      <div class="stat-label">True Positives</div>
      <div class="stat-value">{{ stats.verdicts.get('LIKELY TRUE POSITIVE', 0) }}</div>
      <div class="stat-sub">confirmed threats</div>
      <div class="corner">THP</div>
    </div>
    <div class="stat-card" style="--card-accent:var(--accent4)">
      <div class="stat-label">Avg FP Score</div>
      <div class="stat-value">{{ stats.avg_fp_score }}</div>
      <div class="stat-sub">threat confidence /100</div>
      <div class="corner">MLS</div>
    </div>
  </div>
  <div class="charts-grid">
    <div class="chart-card">
      <div class="chart-title">Severity Distribution</div>
      <div class="chart-container"><canvas id="severityChart"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Alerts Over Time</div>
      <div class="chart-container"><canvas id="timelineChart"></canvas></div>
    </div>
  </div>
  <div class="charts-grid">
    <div class="chart-card">
      <div class="chart-title">Top Source IPs</div>
      {% if stats.top_ips %}
      <table class="ip-table">
        {% set max_count = stats.top_ips[0][1] %}
        {% for ip,count in stats.top_ips %}
        <tr>
          <td>{{ ip }}</td>
          <td class="ip-bar-wrap"><div class="ip-bar"><div class="ip-bar-fill" style="width:{{ (count/max_count*100)|int }}%"></div></div></td>
          <td>{{ count }} hits</td>
        </tr>
        {% endfor %}
      </table>
      {% else %}<div class="no-data">NO IP DATA AVAILABLE</div>{% endif %}
    </div>
    <div class="chart-card">
      <div class="chart-title">ML Verdict Summary</div>
      <div class="verdict-grid">
        <div class="verdict-row verdict-tp">
          <span class="verdict-label">LIKELY TRUE POSITIVE</span>
          <span class="verdict-count">{{ stats.verdicts.get('LIKELY TRUE POSITIVE', 0) }}</span>
        </div>
        <div class="verdict-row verdict-uncertain">
          <span class="verdict-label">UNCERTAIN — MANUAL REVIEW</span>
          <span class="verdict-count">{{ stats.verdicts.get('UNCERTAIN - MANUAL REVIEW RECOMMENDED', 0) }}</span>
        </div>
        <div class="verdict-row verdict-fp">
          <span class="verdict-label">LIKELY FALSE POSITIVE</span>
          <span class="verdict-count">{{ stats.verdicts.get('LIKELY FALSE POSITIVE', 0) }}</span>
        </div>
      </div>
    </div>
  </div>
  <div class="charts-grid">
    <div class="chart-card">
      <div class="chart-title">MITRE ATT&CK Techniques</div>
      <div class="chart-container"><canvas id="mitreChart"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">False Positive Score Distribution</div>
      <div class="chart-container"><canvas id="fpChart"></canvas></div>
    </div>
  </div>
  <div class="chart-card">
    <div class="chart-title">Recent Alert Log</div>
    {% if alerts %}
    <div class="alerts-table-wrap">
      <table class="alerts-table">
        <thead><tr><th>Timestamp</th><th>Rule</th><th>Severity</th><th>Source IP</th><th>MITRE</th><th>FP Score</th><th>Verdict</th></tr></thead>
        <tbody>
          {% for a in alerts[-20:]|reverse %}
          <tr>
            <td>{{ a.get('timestamp','unknown')[:19] }}</td>
            <td>{{ a.get('rule_name','Unknown')[:35] }}</td>
            <td><span class="badge badge-{{ a.get('severity','unknown').lower() }}">{{ a.get('severity','unknown').upper() }}</span></td>
            <td>{{ a.get('source_ip','unknown') }}</td>
            <td>{{ a.get('mitre_technique_id','?') }}</td>
            <td>{% set score=a.get('fp_score',0) %}<span class="score-pill {% if score>=70 %}score-high{% elif score>=40 %}score-mid{% else %}score-low{% endif %}">{{ score }}/100</span></td>
            <td style="font-size:10px">{% set v=a.get('fp_verdict','') %}{% if 'TRUE' in v %}<span style="color:var(--critical)">TRUE POS</span>{% elif 'FALSE' in v %}<span style="color:var(--accent2)">FALSE POS</span>{% else %}<span style="color:var(--accent4)">UNCERTAIN</span>{% endif %}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}<div class="no-data">// NO ALERTS LOGGED YET — RUN THE PIPELINE FIRST</div>{% endif %}
  </div>
</div>
<footer>SOC AUTOMATION PIPELINE &nbsp;|&nbsp; AI-ASSISTED TRIAGE &nbsp;|&nbsp; MITRE ATT&CK MAPPED &nbsp;|&nbsp; CONFIDENTIAL</footer>
<script>
function updateClock(){document.getElementById('clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'}
updateClock();setInterval(updateClock,1000);
const cd={plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(30,58,74,0.5)'},ticks:{color:'#4a6a7a',font:{family:'Share Tech Mono',size:10}}},y:{grid:{color:'rgba(30,58,74,0.5)'},ticks:{color:'#4a6a7a',font:{family:'Share Tech Mono',size:10}}}}};
const sd={{ stats.severity|tojson }};
const sl=Object.keys(sd).map(s=>s.toUpperCase());
const sc=sl.map(l=>l==='CRITICAL'?'rgba(255,77,109,0.8)':l==='HIGH'?'rgba(255,140,66,0.8)':l==='MEDIUM'?'rgba(255,209,102,0.8)':l==='LOW'?'rgba(0,255,157,0.7)':'rgba(74,106,122,0.6)');
new Chart(document.getElementById('severityChart'),{type:'doughnut',data:{labels:sl,datasets:[{data:Object.values(sd),backgroundColor:sc,borderWidth:0,hoverOffset:6}]},options:{plugins:{legend:{display:true,position:'right',labels:{color:'#c9d8e8',font:{family:'Share Tech Mono',size:10},padding:12,boxWidth:12}}},cutout:'65%'}});
const td={{ stats.alerts_over_time|tojson }};
new Chart(document.getElementById('timelineChart'),{type:'line',data:{labels:td.map(d=>d[0]),datasets:[{data:td.map(d=>d[1]),borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.08)',borderWidth:2,fill:true,tension:0.4,pointBackgroundColor:'#00d4ff',pointRadius:4}]},options:{...cd,plugins:{legend:{display:false}}}});
const md={{ stats.top_mitre|tojson }};
new Chart(document.getElementById('mitreChart'),{type:'bar',data:{labels:md.map(d=>d[0]),datasets:[{data:md.map(d=>d[1]),backgroundColor:'rgba(0,255,157,0.2)',borderColor:'rgba(0,255,157,0.8)',borderWidth:1}]},options:{...cd,indexAxis:'y',plugins:{legend:{display:false}}}});
const fb={{ stats.fp_buckets|tojson }};
new Chart(document.getElementById('fpChart'),{type:'bar',data:{labels:Object.keys(fb),datasets:[{data:Object.values(fb),backgroundColor:['rgba(0,255,157,0.6)','rgba(0,255,157,0.4)','rgba(255,209,102,0.5)','rgba(255,140,66,0.6)','rgba(255,77,109,0.7)'],borderWidth:0}]},options:{...cd,plugins:{legend:{display:false}}}});
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    alerts = load_alert_log()
    stats = get_stats(alerts)
    return render_template_string(HTML, stats=stats, alerts=alerts)

@app.route("/api/stats")
def api_stats():
    alerts = load_alert_log()
    return jsonify(get_stats(alerts))

if __name__ == "__main__":
    print("[*] SOC Dashboard starting at http://0.0.0.0:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
