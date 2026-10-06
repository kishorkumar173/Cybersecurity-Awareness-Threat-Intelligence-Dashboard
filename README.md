# Cybersecurity Awareness & Threat Intelligence Dashboard

> **Defensive Security Notice:**
> This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems. All indicators follow safe RFC/documentation allocations (RFC 5737, RFC 2606) and are analyzed strictly as passive telemetry.

---

## 🛡️ Project Overview
The **Cybersecurity Awareness & Threat Intelligence Dashboard** is an enterprise-grade, defensive security operations center (SOC) and cyber education platform. It harmonizes two critical pillars of modern cyber resilience:
1. **Technical Cyber Threat Intelligence (CTI):** Ingestion, syntactic validation, local enrichment, multi-factor risk/confidence scoring, correlation clustering, and MITRE ATT&CK mapping across 2,250+ threat records.
2. **Human Defense Layer:** 15 modular cybersecurity awareness micro-curricula and an interactive 32-question scenario-based quiz engine providing personalized learning guidance.

---

## 🎯 Problem Statement & Industry Relevance
Modern security teams face two persistent challenges:
- **Alert Fatigue & IOC Staleness:** Disconnected feeds overwhelm SOC Tier-1 analysts with duplicate, uncontextualized indicators where match does not necessarily indicate compromise.
- **The Human Boundary Gap:** Over 80% of enterprise intrusions originate at the human boundary (phishing, social engineering, password reuse). Traditional security tools treat end users as liabilities rather than trained defensive sensors.

This project bridges technical threat intelligence with proactive human defense, demonstrating how SOCs correlate indicators into deduplicated alert clusters while simultaneously delivering contextual awareness to avoid initial access.

---

## 🏛️ System Architecture
```
  Synthetic / Public Defensive Threat Data (CSV)
                      ↓
             Data Ingestion Layer
                      ↓
         Normalization & Deduplication
                      ↓
            IOC Validation Engine
        (RFC 5737, IPv6, FQDN, Hashes, CVE)
                      ↓
            Threat Enrichment Engine
      (Sightings, Categories, Sources, ATT&CK)
                      ↓
        Multi-Factor Risk & Confidence Engine
                      ↓
         Correlation & Clustering Engine
                      ↓
 ┌────────────────────┼───────────────────────┐
 ↓                    ↓                       ↓
Threat Database    Alert Engine       MITRE ATT&CK Mapping
 (SQLite Store)   (Fatigue Reducer)     (Tactics & Techniques)
 └────────────────────┼───────────────────────┘
                      ↓
       REST API Backend (Python Flask)
                      ↓
      Vibrant Responsive SOC Dashboard
    (Emerald, Violet, Coral, Amber Theme)
                      ↓
   Interactive Security Awareness & Quiz Center
```

---

## 🔑 Crucial Defensive Principles
The platform reinforces core defensive distinctions:
* **OBSERVATION:** A raw sighting recorded by telemetry.
* **INDICATOR:** An artifact normalized and syntactically validated.
* **ALERT:** A prioritized notification exceeding risk thresholds.
* **THREAT:** Contextualized intelligence indicating potential adversary activity.
* **INCIDENT:** A confirmed adverse event threatening confidentiality, integrity, or availability.

> **Key Rule:** High Risk $\neq$ Confirmed Compromise. An indicator match alone never proves active exploitation.

---

## 🧮 Multi-Factor Risk & Confidence Scoring

### 1. Risk Score (0 – 100)
Calculated via a balanced, weighted defensive formulation:
$$\text{Risk Score} = 0.30 \times \text{Severity} + 0.25 \times \text{Confidence} + 0.15 \times \text{Recency} + 0.10 \times \text{Observations} + 0.10 \times \text{Source} + 0.10 \times \text{Context}$$

* **0–20:** Informational
* **21–40:** Low
* **41–60:** Medium
* **61–80:** High
* **81–100:** Critical

### 2. Analytical Confidence (0 – 100)
Measures the evidentiary reliability of the reporting source and analytical certainty, completely decoupled from severity. (e.g., Risk: 90 / Confidence: 25 vs. Risk: 70 / Confidence: 95).

### 3. Vulnerability Prioritization
Extends standard CVSS by integrating asset criticality, internet-facing exposure, and exploit evidence:
$$\text{Priority Score} = (\text{CVSS} \times 10 \times \text{Asset Multiplier} \times \text{Exposure Multiplier}) + \text{Exploitation Factor}$$

---

## 📊 Core Features

1. **Threat Intelligence Feed:** 2,250+ normalized defensive records across 10 security domains.
2. **IOC Validation Engine:** Validates RFC 5737 IPv4, IPv6, FQDNs, URLs, MD5, SHA-1, SHA-256, and CVE IDs.
3. **IOC Search Tool:** Instant offline database search with zero external probing.
4. **Correlation Engine:** Clusters indicators by campaign and observation window; dedupes recurring alerts to eliminate SOC fatigue.
5. **MITRE ATT&CK Matrix Alignment:** Maps tactics and techniques where evidence is justified.
6. **SOC Investigation View:** Interactive dossier with threat timeline, analyst notes, and status management.
7. **Vulnerability Awareness Module:** Contextual prioritization of CVE flaws.
8. **Security Awareness Center:** 15 micro-learning modules (Phishing, MFA Fatigue, Ransomware, USB safety, AI scams).
9. **Interactive Quiz Engine:** 32 scenario-based questions with instant score categorization and tailored learning paths.
10. **Executive Cybersecurity Summary:** High-level posture metrics for leadership and CISOs.

---

## 💻 Tech Stack
* **Backend:** Python 3.13, Flask 3.0, Flask-CORS
* **Data Processing & Analytics:** Pandas, NumPy
* **Database:** SQLite3 Relational Engine with Indexing
* **Frontend:** Modern HTML5, Responsive CSS3 (Vibrant Emerald / Violet / Coral theme), JavaScript ES6+
* **Visualization:** Chart.js 4.4
* **Testing:** Pytest (37 automated test scenarios, 100% passing)

---

## 🚀 Quickstart & Execution Guide

### Step 1: Clone or Navigate to Directory
```powershell
cd "E:\IIT PROJECT\CYBERSECURITY"
```

### Step 2: Set Up Virtual Environment (Optional) & Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Generate Dataset & Initialize Database
```powershell
python data/generate_threat_data.py
python backend/models/database.py
```

### Step 4: Run Automated Tests
```powershell
pytest tests/test_dashboard.py -v
```
*(All 37 test cases will execute and verify syntax, scoring, correlation, and API routes)*

### Step 5: Start Defensive Dashboard
```powershell
python backend/app.py
```

Open your browser at:
👉 **`http://127.0.0.1:5000`**

---

## 🧪 Safe Demonstration Walkthrough

1. **Open the SOC Dashboard (`http://127.0.0.1:5000`)**
   Observe the top metrics, threat category distribution, and severity breakdown in the vibrant Emerald & Violet interface.
2. **Search an Indicator**
   In the IOC Search box, input the benchmark indicator:
   `198.51.100.25` or `login-check.invalid`
   Click **Analyze Indicator** to inspect defensive risk, sightings, and guidance without triggering outbound requests.
3. **Inspect Threat Dossier**
   Click on Threat ID `THR-2026-001` to view its ATT&CK mapping (`T1566.002 - Spearphishing Link`), correlation cluster, and write analyst triage notes.
4. **Complete Security Awareness Quiz**
   Navigate to **Security Quiz**, answer the 32 real-world questions, submit, and inspect your awareness score, vector breakdown, and tailored remediation modules.

---

## 📜 Ethical & Educational Disclaimer
This repository is engineered solely for academic demonstration, defensive engineering, and security training. The code contains no exploits, no malware delivery stubs, no active scanner mechanisms, and strictly adheres to safe, documentation-reserved IP/domain conventions.
