# SOC Automation Pipeline

### AI-Powered Threat Triage, MITRE ATT&CK Mapping & Incident Response

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Elastic](https://img.shields.io/badge/Elastic-SIEM-005571?style=flat-square&logo=elastic)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20%2F%20phi3:mini-black?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Overview

This project is a proof-of-concept SOC (Security Operations Centre) automation pipeline that addresses one of the biggest challenges in enterprise security today: **alert fatigue**.

SOC analysts are drowning in thousands of alerts daily — the majority of which are false positives. This pipeline demonstrates how AI can automatically triage, classify, and respond to SIEM alerts without human intervention, mirroring what vendors like Microsoft Sentinel, Palo Alto XSIAM, and CrowdStrike Charlotte AI are actively building and selling.

> **This is not just a lab exercise.** It is a working proof-of-concept for a real problem that companies are actively spending millions to solve.

---

## What It Does

When a security alert fires in Elastic SIEM, instead of an analyst manually investigating it, the pipeline:

1. **Detects** — Polls Elastic SIEM automatically for new open alerts
2. **Understands** — Sends the alert to a local LLM (phi3:mini via Ollama) for AI-powered triage
3. **Contextualises** — Maps the alert to the MITRE ATT&CK framework, identifying the technique, tactic, and predicted next steps in the attack chain
4. **Scores** — Runs a ML-ready false positive scorer to determine whether the alert is a genuine threat or noise
5. **Responds** — Generates a recommended analyst runbook with immediate containment steps
6. **Documents** — Produces a formal PDF incident report automatically
7. **Visualises** — Displays all processed alerts in a real-time web dashboard

---

## Architecture

```
Elastic SIEM (Kibana)
        │
        │  REST API (Elasticsearch Query)
        ▼
┌─────────────────────────────────────────┐
│         SOC Automation Pipeline         │
│                                         │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ Alert Parser│───▶│ MITRE Mapper   │  │
│  └─────────────┘    └────────────────┘  │
│          │                  │           │
│          ▼                  ▼           │
│  ┌─────────────┐    ┌────────────────┐  │
│  │  FP Scorer  │    │  Ollama LLM    │  │
│  │  (ML-Ready) │    │  (phi3:mini)   │  │
│  └─────────────┘    └────────────────┘  │
│          │                  │           │
│          └──────────┬───────┘           │
│                     ▼                   │
│           ┌──────────────────┐          │
│           │  PDF Report Gen  │          │
│           └──────────────────┘          │
│                     │                   │
│                     ▼                   │
│           ┌──────────────────┐          │
│           │  alert_log.json  │          │
│           └──────────────────┘          │
└─────────────────────────────────────────┘
        │
        ▼
  Flask Dashboard (http://localhost:5000)
```

---

## Key Features

### AI-Powered Triage

The pipeline sends each alert to a locally-hosted LLM (phi3:mini via Ollama) with a structured prompt that returns:

- Severity assessment (true positive / false positive likelihood)
- Attack summary and attacker intent
- Recommended response runbook (5 immediate actions)
- Containment recommendations
- Investigation notes for the analyst

### MITRE ATT&CK Mapping

Each alert is automatically mapped to the MITRE ATT&CK framework, including:

- Technique ID and name (e.g. T1110 — Brute Force)
- Tactic (e.g. Credential Access)
- Predicted next steps in the attack chain

### ML False Positive Scorer

A scoring engine evaluates each alert on multiple weighted factors:

- Risk score from Elastic
- Time of day (off-hours activity weighted higher)
- Known malicious IP matching
- Rule fidelity (historically noisy vs. high-signal rules)
- MITRE tactic severity weighting

Each alert receives a **0–100 confidence score** and a verdict:

- `LIKELY TRUE POSITIVE` (≥ 70)
- `UNCERTAIN — MANUAL REVIEW RECOMMENDED` (40–69)
- `LIKELY FALSE POSITIVE` (< 40)

> The scorer is architected to be ML-ready: once sufficient labeled data is collected, the rule-based engine can be replaced with a trained `RandomForestClassifier` from scikit-learn with zero changes to the rest of the pipeline.

### Automated PDF Incident Reports

Every processed alert generates a formal PDF report including:

- Incident metadata (alert ID, timestamp, rule triggered)
- Attack details (source IP, target host, username, process)
- MITRE ATT&CK mapping
- ML false positive analysis with scoring breakdown
- Full AI triage analysis and runbook
- Analyst sign-off section

### Real-Time Web Dashboard

A Flask-powered dashboard visualises the full pipeline output:

- Total alerts processed, reports generated, confirmed threats
- Severity breakdown (doughnut chart)
- Alerts over time (timeline chart)
- Top source IPs with hit frequency
- MITRE ATT&CK technique distribution
- False positive score histogram
- ML verdict summary
- Recent alert log table

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| SIEM | Elastic Security / Kibana 9.x |
| Log Shipping | Filebeat |
| AI / LLM | Ollama + phi3:mini (3.8B) |
| ML Scoring | Custom rule-based scorer (scikit-learn ready) |
| PDF Generation | fpdf2 |
| Dashboard | Flask + Chart.js |
| Attack Simulation | Kali Linux |
| Language | Python 3.10+ |

---

## Setup & Installation

### Prerequisites

- Ubuntu 22.04 / 24.04
- Elastic Stack 9.x (Elasticsearch + Kibana + Filebeat)
- Ollama installed on host machine with GPU support
- Python 3.10+

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/soc-automation-pipeline.git
cd soc-automation-pipeline
```

### 2. Install Python Dependencies

```bash
pip install requests fpdf2 ollama flask --break-system-packages
```

### 3. Configure Ollama

Install Ollama on your host machine and pull the model:

```bash
ollama pull phi3:mini
```

If running Ollama on a separate machine (e.g. Windows host with GPU), set the host environment variable:

```bash
export OLLAMA_HOST=http://192.168.1.X:11434
```

### 4. Configure the Pipeline

Edit the configuration section at the top of `soc_automation.py`:

```python
ELASTIC_URL      = "https://localhost:9200"
ELASTIC_API_KEY  = "your_api_key_here"
OLLAMA_MODEL     = "phi3:mini"
WHITELISTED_IPS  = ["your_analyst_machine_ip"]
KNOWN_BAD_IPS    = ["your_attacker_ip"]
```

### 5. Run the Pipeline

```bash
python3 soc_automation.py
```

### 6. Run the Dashboard

```bash
python3 dashboard.py
```

Open `http://your_vm_ip:5000` in your browser.

---

## Project Structure

```
soc-automation-pipeline/
│
├── soc_automation.py       # Main pipeline script
├── dashboard.py            # Flask web dashboard
├── .gitignore              # Files to exclude from version control
└── README.md               # Project documentation
```

---

## Example Output

### Terminal

```
[*] SOC Automation Pipeline Starting...
[*] Fetching alerts from Elastic SIEM...
[*] Found 19 alerts. Processing new ones...

[+] Processing alert: SSH Brute Force | Severity: high | Source: 192.168.56.101
    MITRE: T1110 - Brute Force
    FP Score: 85/100 — LIKELY TRUE POSITIVE
    Sending to Ollama for triage...
    Report saved: reports/incident_a3f2b1c4_2026-03-12.pdf

[*] Done. Processed 19 alerts. Reports saved to ./reports/
```

---

## Real-World Relevance

This project directly mirrors what enterprise security vendors are building:

| Vendor | Product | Equivalent Feature |
|--------|---------|-------------------|
| Microsoft | Sentinel + Copilot for Security | AI-assisted alert triage |
| Palo Alto | XSIAM | Automated incident response |
| CrowdStrike | Charlotte AI | Natural language threat investigation |
| Splunk | SOAR | Automated runbook generation |

The core problem — analysts spending hours manually triaging alerts that turn out to be false positives — costs enterprises millions annually. AI triage is the industry's proposed solution and this pipeline demonstrates that architecture at a functional level.

---

## Future Improvements

- Replace rule-based FP scorer with a trained `RandomForestClassifier` once labeled data is sufficient
- Add email / Slack notifications when high-severity true positives are detected
- Implement continuous polling with configurable intervals
- Integrate threat intelligence feeds (VirusTotal, AbuseIPDB) for IP enrichment
- Add user authentication to the dashboard

---

## Author

**Ahmad Bussti**

Cybersecurity Student | Aspiring SOC Analyst

[LinkedIn](https://linkedin.com/in/ahmad-bussti-7bb574359/) · [GitHub](https://github.com/abussti)

---

*Built as a proof-of-concept demonstrating AI-assisted SOC automation. All testing performed in an isolated lab environment.*
