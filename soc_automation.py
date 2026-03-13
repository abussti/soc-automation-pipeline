"""
SOC Automation Pipeline
Polls Elastic SIEM for alerts, triages them with Ollama/Mistral,
maps to MITRE ATT&CK, generates response runbooks, and produces PDF incident reports.
"""

import requests
import json
import os
from datetime import datetime
from fpdf import FPDF
import ollama
ollama_client = ollama.Client(host="OLLAMA_HOST")

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
ELASTIC_URL = "https://localhost:9200"
ELASTIC_API_KEY = "your_elastic_api_key_here"
ALERTS_INDEX = ".alerts-security.alerts-default"
OLLAMA_MODEL = "phi3:mini"
REPORTS_DIR = "reports"
PROCESSED_IDS_FILE = "processed_alerts.json"
WHITELISTED_IPS = [
    "your_analyst_ip_here",  # analyst machine
]

# ─────────────────────────────────────────────
# FALSE POSITIVE SCORER
# ─────────────────────────────────────────────
import re

KNOWN_BAD_IPS = [
    "your_attacker_ip_here",
]

# Rules that are historically noisy / low fidelity
NOISY_RULES = [
    "port scan",
    "network sweep",
]

# Rules that are high fidelity / almost always true positives
HIGH_FIDELITY_RULES = [
    "brute force",
    "ssh login",
    "privilege escalation",
    "malware",
]

class FalsePositiveScorer:
    """
    Scores alerts on likelihood of being a TRUE POSITIVE (0-100).

    Higher score = more likely a real attack.
    Lower score = more likely a false positive.

    Architecture is ML-ready: scoring logic can be replaced with a
    trained RandomForestClassifier once sufficient labeled data exists.
    """

    def score(self, alert, mitre):
        score = 50  # start neutral
        reasons = []

        # ── Risk Score Weight ──
        risk = int(alert.get("risk_score", 0))
        if risk >= 73:
            score += 20
            reasons.append(f"High risk score ({risk})")
        elif risk >= 47:
            score += 10
            reasons.append(f"Medium risk score ({risk})")
        else:
            score -= 10
            reasons.append(f"Low risk score ({risk})")

        # ── Known Bad IP ──
        if alert.get("source_ip") in KNOWN_BAD_IPS:
            score += 25
            reasons.append("Source IP matches known bad IP list")

        # ── Time of Day (off-hours = more suspicious) ──
        try:
            timestamp = alert.get("timestamp", "")
            hour = int(timestamp[11:13])  # extract hour from ISO timestamp
            if hour >= 22 or hour <= 5:
                score += 15
                reasons.append(f"Alert triggered during off-hours ({hour:02d}:00)")
            elif 9 <= hour <= 17:
                score -= 5
                reasons.append(f"Alert triggered during business hours ({hour:02d}:00)")
        except:
            pass

        # ── Rule Fidelity ──
        rule_lower = alert.get("rule_name", "").lower()
        if any(r in rule_lower for r in HIGH_FIDELITY_RULES):
            score += 20
            reasons.append("Rule is high fidelity (low false positive rate)")
        elif any(r in rule_lower for r in NOISY_RULES):
            score -= 20
            reasons.append("Rule is historically noisy (high false positive rate)")

        # ── MITRE Tactic Weight ──
        tactic = mitre.get("tactic", "").lower()
        if tactic in ["lateral movement", "privilege escalation", "exfiltration"]:
            score += 15
            reasons.append(f"High-severity MITRE tactic: {mitre['tactic']}")
        elif tactic in ["discovery", "reconnaissance"]:
            score -= 5
            reasons.append(f"Early-stage MITRE tactic: {mitre['tactic']}")

        # ── Unknown Source IP ──
        if alert.get("source_ip") == "unknown":
            score -= 10
            reasons.append("No source IP (host-based detection, lower confidence)")

        # ── Clamp score between 0 and 100 ──
        score = max(0, min(100, score))

        # ── Verdict ──
        if score >= 70:
            verdict = "LIKELY TRUE POSITIVE"
        elif score >= 40:
            verdict = "UNCERTAIN - MANUAL REVIEW RECOMMENDED"
        else:
            verdict = "LIKELY FALSE POSITIVE"

        return {
            "score": score,
            "verdict": verdict,
            "reasons": reasons
        }

# Instantiate scorer globally
fp_scorer = FalsePositiveScorer()



def log_alert_for_dashboard(alert, mitre, fp_result):
    """Append alert data to the dashboard log file."""
    log_entry = {
        "timestamp": alert["timestamp"],
        "rule_name": alert["rule_name"],
        "severity": alert["severity"],
        "risk_score": alert["risk_score"],
        "source_ip": alert["source_ip"],
        "hostname": alert["hostname"],
        "mitre_technique": mitre["technique_name"],
        "mitre_technique_id": mitre["technique_id"],
        "mitre_tactic": mitre["tactic"],
        "fp_score": fp_result["score"],
        "fp_verdict": fp_result["verdict"],
    }
    log = []
    if os.path.exists("alert_log.json"):
        with open("alert_log.json", "r") as f:
            log = json.load(f)
    log.append(log_entry)
    with open("alert_log.json", "w") as f:
        json.dump(log, f, indent=2)

# ─────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────
MITRE_MAPPING = {
    "brute force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "next_steps": "Attacker likely to attempt lateral movement or privilege escalation next."
    },
    "ssh login": {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "next_steps": "Attacker has gained access. Expect reconnaissance commands, privilege escalation, or persistence mechanisms."
    },
    "port scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "next_steps": "Attacker is in reconnaissance phase. Credential attacks or exploitation attempts likely to follow."
    },
    "authentication failure": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "next_steps": "Monitor for successful authentication from same source IP."
    }
}

def is_whitelisted(alert):
    return alert.get("source_ip") in WHITELISTED_IPS

def load_processed_ids():
    """Load previously processed alert IDs to avoid duplicates."""
    if os.path.exists(PROCESSED_IDS_FILE):
        with open(PROCESSED_IDS_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_processed_ids(ids):
    """Save processed alert IDs."""
    with open(PROCESSED_IDS_FILE, "w") as f:
        json.dump(list(ids), f)


def fetch_alerts():
    """Fetch alerts from Elastic SIEM."""
    headers = {
        "Authorization": f"ApiKey {ELASTIC_API_KEY}",
        "Content-Type": "application/json"
    }
    query = {
        "query": {
            "term": {
                "kibana.alert.workflow_status": "open"
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 50
    }
    try:
        response = requests.post(
            f"{ELASTIC_URL}/{ALERTS_INDEX}/_search",
            headers=headers,
            json=query,
            verify=False  # self-signed cert in lab
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch alerts: {e}")
        return []


def parse_alert(alert):
    """Extract relevant fields from raw alert JSON."""
    source = alert.get("_source", {})

    # Source IP - try multiple locations
    source_ip = (
        source.get("source", {}).get("ip") or
        source.get("client", {}).get("ip") or
        (source.get("related", {}).get("ip", [None])[0]) or
        "unknown"
    )

    # Event category
    event_category = source.get("event", {}).get("category", ["unknown"])
    if isinstance(event_category, list):
        event_category = ", ".join(event_category)

    return {
        "id": alert.get("_id", "unknown"),
        "rule_name": source.get("kibana.alert.rule.name", "Unknown Rule"),
        "severity": source.get("kibana.alert.severity", "unknown"),
        "risk_score": source.get("kibana.alert.risk_score", 0),
        "reason": source.get("kibana.alert.reason", "No reason provided"),
        "timestamp": source.get("@timestamp", "unknown"),

        "source_ip": source_ip,
        "source_port": source.get("source", {}).get("port", "unknown"),
        "username": source.get("user", {}).get("name") or source.get("log", {}).get("syslog", {}).get("appname") or "unknown",
        "hostname": source.get("host", {}).get("name") or source.get("host", {}).get("hostname") or "unknown",
        "message": source.get("message", "No message"),
        "process": source.get("process", {}).get("name", "unknown"),
        "event_action": source.get("event", {}).get("action", "unknown"),
        "event_outcome": source.get("event", {}).get("outcome", "unknown"),
        "event_category": event_category,
        "log_file": source.get("log", {}).get("file", {}).get("path", "unknown"),
        "os": source.get("host", {}).get("os", {}).get("name", "unknown"),
        "agent_name": source.get("agent", {}).get("name", "unknown"),
    }

def map_to_mitre(alert):
    """Map alert to MITRE ATT&CK technique based on rule name."""
    rule_name_lower = alert["rule_name"].lower()
    for keyword, mapping in MITRE_MAPPING.items():
        if keyword in rule_name_lower:
            return mapping
    return {
        "technique_id": "T????",
        "technique_name": "Unknown Technique",
        "tactic": "Unknown Tactic",
        "next_steps": "Manual investigation required."
    }


def triage_with_ai(alert, mitre):
    """Send alert to Ollama/Mistral for AI triage."""
    prompt = f"""You are a SOC analyst. Analyze this security alert and provide a structured triage report.

ALERT DETAILS:
- Rule: {alert['rule_name']}
- Severity: {alert['severity']}
- Risk Score: {alert['risk_score']}
- Timestamp: {alert['timestamp']}
- Source IP: {alert['source_ip']}
- Target Host: {alert['hostname']}
- Username: {alert['username']}
- Message: {alert['message']}
- MITRE Technique: {mitre['technique_id']} - {mitre['technique_name']}
- MITRE Tactic: {mitre['tactic']}

Provide your response in exactly this format:

SEVERITY ASSESSMENT:
[Your assessment of severity and whether this is likely a true positive or false positive]

ATTACK SUMMARY:
[Brief description of what the attacker is doing and their likely goal]

MITRE ATT&CK ANALYSIS:
[Analysis of the technique being used and what stage of the attack chain this represents]

IMMEDIATE RESPONSE RUNBOOK:
1. [First action]
2. [Second action]
3. [Third action]
4. [Fourth action]
5. [Fifth action]

CONTAINMENT RECOMMENDATIONS:
[Specific containment steps for this alert type]

INVESTIGATION NOTES:
[What an analyst should look for when investigating this alert]"""

    try:
        response = ollama_client.chat(
                model=OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}],
                options={
                        "temperature": 0.1,
                        "num_predict": 400,
                        "num_ctx": 2048,
                }
        )
        return response["message"]["content"]
    except Exception as e:
        return f"AI triage failed: {e}"


class IncidentReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, "SOC INCIDENT REPORT", align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | Generated by SOC Automation Pipeline | CONFIDENTIAL", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(220, 220, 220)
        self.cell(0, 8, title, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def field_row(self, label, value):
        self.set_font("Helvetica", "B", 9)
        self.multi_cell(0, 7, f"{label}: {str(value)}")
        self.ln(1)

    def body_text(self, text):
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 6, text)
        self.ln(2)


def generate_pdf_report(alert, mitre, ai_triage, fp_result):
    """Generate a PDF incident report."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp_safe = alert["timestamp"].replace(":", "-").replace(".", "-")
    filename = f"{REPORTS_DIR}/incident_{alert['id'][:8]}_{timestamp_safe}.pdf"

    pdf = IncidentReportPDF()
    pdf.add_page()

    # ── Header Info ──
    pdf.section_title("INCIDENT METADATA")
    pdf.field_row("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.field_row("Alert ID", alert["id"])
    pdf.field_row("Detection Time", alert["timestamp"])
    pdf.field_row("Rule Triggered", alert["rule_name"])
    pdf.field_row("Severity", alert["severity"].upper())
    pdf.field_row("Risk Score", str(alert["risk_score"]) + " / 100")
    pdf.ln(4)

    # ── Attack Details ──
    pdf.section_title("ATTACK DETAILS")
    pdf.field_row("Source IP", alert["source_ip"])
    pdf.field_row("Source Port", str(alert["source_port"]))
    pdf.field_row("Target Host", alert["hostname"])
    pdf.field_row("Target Username", alert["username"])
    pdf.field_row("Process", alert["process"])
    pdf.field_row("Event Category", alert["event_category"])
    pdf.field_row("Event Action", alert["event_action"])
    pdf.field_row("Event Outcome", alert["event_outcome"])
    pdf.field_row("Log File", alert["log_file"])
    pdf.field_row("Operating System", alert["os"])
    pdf.field_row("Agent", alert["agent_name"])
    pdf.field_row("Raw Message", alert["message"])
    pdf.ln(4)

    # ── MITRE ATT&CK ──
    pdf.section_title("MITRE ATT&CK MAPPING")
    pdf.field_row("Technique ID", mitre["technique_id"])
    pdf.field_row("Technique Name", mitre["technique_name"])
    pdf.field_row("Tactic", mitre["tactic"])
    pdf.field_row("Predicted Next Steps", mitre["next_steps"])
    pdf.ln(4)

    # ── False Positive Score ──
    pdf.section_title("ML FALSE POSITIVE ANALYSIS")
    pdf.field_row("Confidence Score", f"{fp_result['score']} / 100")
    pdf.field_row("Verdict", fp_result['verdict'])
    pdf.field_row("Scoring Factors", " | ".join(fp_result['reasons']))
    pdf.ln(4)

    # ── AI Triage ──
    pdf.section_title("AI-POWERED TRIAGE ANALYSIS")
    pdf.body_text(ai_triage)
    pdf.ln(4)

    # ── Analyst Sign-off ──
    pdf.section_title("ANALYST SIGN-OFF")
    pdf.field_row("Reviewed By", "________________________")
    pdf.field_row("Date", "________________________")
    pdf.field_row("Status", "[ ] True Positive    [ ] False Positive    [ ] Under Investigation")

    pdf.output(filename)
    return filename


def main():
    print("[*] SOC Automation Pipeline Starting...")
    print("[*] Fetching alerts from Elastic SIEM...")

    # Suppress SSL warnings for self-signed cert
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    processed_ids = load_processed_ids()
    alerts = fetch_alerts()

    if not alerts:
        print("[*] No alerts found.")
        return

    print(f"[*] Found {len(alerts)} alerts. Processing new ones...")

    new_alerts = [a for a in alerts if a.get("_id") not in processed_ids]

    if not new_alerts:
        print("[*] No new alerts to process.")
        return

    print(f"[*] Processing {len(new_alerts)} new alerts...")


    for raw_alert in new_alerts:
        alert = parse_alert(raw_alert)
        print(f"\n[+] Processing alert: {alert['rule_name']} | Severity: {alert['severity']} | Source: {alert['source_ip']}")

        # Skip whitelisted IPs
        if is_whitelisted(alert):
            print(f"    [SKIPPED] Whitelisted IP: {alert['source_ip']}")
            processed_ids.add(alert["id"])
            continue

        # Map to MITRE ATT&CK
        mitre = map_to_mitre(alert)
        print(f"    MITRE: {mitre['technique_id']} - {mitre['technique_name']}")

        # False Positive Scoring
        fp_result = fp_scorer.score(alert, mitre)
        log_alert_for_dashboard(alert, mitre, fp_result)
        print(f"    FP Score: {fp_result['score']}/100 — {fp_result['verdict']}")

        # AI Triage
        print(f"    Sending to Ollama for triage...")
        ai_triage = triage_with_ai(alert, mitre)

        # Generate PDF report
        report_path = generate_pdf_report(alert, mitre, ai_triage, fp_result)
        print(f"    Report saved: {report_path}")

        # Mark as processed
        processed_ids.add(alert["id"])

    save_processed_ids(processed_ids)
    print(f"\n[*] Done. Processed {len(new_alerts)} alerts. Reports saved to ./{REPORTS_DIR}/")


if __name__ == "__main__":
    main()
