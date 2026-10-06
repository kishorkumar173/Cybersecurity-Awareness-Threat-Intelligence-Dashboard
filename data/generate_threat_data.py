"""
Synthetic Threat Intelligence & Vulnerability Data Generator
Safe, defensive, sanitized threat dataset generator producing >= 2,200 records.
All indicators strictly adhere to safe RFC/documentation standards:
- IPv4: RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
- IPv6: RFC 3849 (2001:db8::/32)
- Domains: RFC 2606 / RFC 6761 (example.com, example.org, example.net, *.invalid)
- Hashes: Synthetic SHA-256 strings clearly tagged DEMO
"""

import os
import random
import hashlib
import csv
from datetime import datetime, timedelta

random.seed(42)

TOTAL_RECORDS = 2250

THREAT_CATEGORIES = [
    "PHISHING",
    "MALWARE",
    "RANSOMWARE",
    "CREDENTIAL THREATS",
    "WEB THREATS",
    "NETWORK THREATS",
    "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING",
    "DATA EXPOSURE",
    "ACCOUNT SECURITY"
]

INDICATOR_TYPES = [
    "IP ADDRESS",
    "DOMAIN",
    "URL",
    "FILE HASH",
    "EMAIL/SENDER DOMAIN",
    "CVE ID"
]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

SOURCES = [
    ("Internal SOC", "A – Highly Reliable"),
    ("Security Vendor", "A – Highly Reliable"),
    ("Public Threat Feed", "B – Usually Reliable"),
    ("Research Report", "B – Usually Reliable"),
    ("Community Submission", "C – Fairly Reliable"),
    ("Unknown Source", "D – Reliability Unknown")
]

MITRE_MAPPINGS = {
    "PHISHING": [
        ("Initial Access", "Phishing: Spearphishing Link", "T1566.002"),
        ("Initial Access", "Phishing: Spearphishing Attachment", "T1566.001"),
        ("Initial Access", "Phishing: Spearphishing Voice", "T1566.004")
    ],
    "MALWARE": [
        ("Execution", "User Execution: Malicious File", "T1204.002"),
        ("Defense Evasion", "Obfuscated Files or Information", "T1027"),
        ("Command and Control", "Application Layer Protocol", "T1071")
    ],
    "RANSOMWARE": [
        ("Impact", "Data Encrypted for Impact", "T1486"),
        ("Infiltration", "Lateral Movement: SMB/Windows Admin Shares", "T1021.002"),
        ("Impact", "Inhibit System Recovery", "T1490")
    ],
    "CREDENTIAL THREATS": [
        ("Credential Access", "Brute Force: Password Spraying", "T1110.003"),
        ("Credential Access", "OS Credential Dumping", "T1003"),
        ("Credential Access", "Credentials in Files", "T1552.001")
    ],
    "WEB THREATS": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        ("Collection", "Automated Collection: Web Scraping", "T1119"),
        ("Command and Control", "Web Service: Dead Drop Resolver", "T1102.001")
    ],
    "NETWORK THREATS": [
        ("Discovery", "Network Service Scanning", "T1046"),
        ("Command and Control", "Protocol Tunneling", "T1572"),
        ("Discovery", "Network Sniffing", "T1040")
    ],
    "VULNERABILITY EXPOSURE": [
        ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        ("Privilege Escalation", "Exploitation for Privilege Escalation", "T1068"),
        ("Lateral Movement", "Exploitation of Remote Services", "T1210")
    ],
    "SOCIAL ENGINEERING": [
        ("Initial Access", "Replication Through Removable Media", "T1091"),
        ("Execution", "User Execution: Malicious Link", "T1204.001"),
        ("Initial Access", "Trusted Relationship", "T1199")
    ],
    "DATA EXPOSURE": [
        ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
        ("Exfiltration", "Exfiltration Over Alternative Protocol", "T1048"),
        ("Collection", "Data from Cloud Storage", "T1530")
    ],
    "ACCOUNT SECURITY": [
        ("Persistence", "Account Manipulation: Additional Credentials", "T1098.001"),
        ("Defense Evasion", "Valid Accounts: Cloud Accounts", "T1078.004"),
        ("Persistence", "Create Account: Local Account", "T1136.001")
    ]
}

COUNTRIES = ["US", "DE", "GB", "NL", "JP", "SG", "AU", "CA", "FR", "IN", "BR", "CH", "Global"]

SAFE_IPV4_PREFIXES = [
    (192, 0, 2),      # RFC 5737 TEST-NET-1
    (198, 51, 100),   # RFC 5737 TEST-NET-2
    (203, 0, 113)     # RFC 5737 TEST-NET-3
]

SAFE_DOMAINS = [
    "login-check.invalid", "auth-gateway.example.com", "update-service.example.org",
    "telemetry-sync.example.net", "corp-portal-test.invalid", "cdn-cache.example.com",
    "doc-share.example.org", "invoice-verify.invalid", "security-alert.example.net",
    "support-desk.invalid", "client-token.example.org", "session-manager.invalid"
]

SAFE_URL_PATHS = [
    "/verify-account/prompt", "/download/security-patch.bin", "/auth/login-redirect",
    "/invoice/preview-doc.pdf", "/session/token-exchange", "/api/v1/health-check",
    "/update/agent-installer", "/secure/portal/auth"
]

SAMPLE_CVES = [
    ("CVE-2026-1042", "High", 7.8, "Apache Struts Deserialization Demo", "Web Application Server"),
    ("CVE-2026-2189", "Critical", 9.8, "OpenSSL Buffer Overflow Demo", "Cryptographic Library"),
    ("CVE-2026-3390", "Medium", 5.4, "Linux Kernel Privilege Escalation Demo", "Operating System"),
    ("CVE-2026-4401", "High", 8.2, "Kubernetes API Authorization Bypass Demo", "Container Orchestration"),
    ("CVE-2026-5512", "Critical", 9.1, "Log4j Remote Code Execution Demo Variant", "Logging Framework"),
    ("CVE-2026-6623", "Low", 3.7, "Nginx Header Information Disclosure Demo", "Web Server"),
    ("CVE-2026-7734", "High", 8.6, "PostgreSQL SQL Parsing Memory Corruption Demo", "Database Server"),
    ("CVE-2026-8845", "Critical", 9.5, "Microsoft Exchange RPC Flaw Demo", "Enterprise Mail"),
    ("CVE-2026-9956", "Medium", 6.3, "Cisco IOS XE CLI Path Traversal Demo", "Network Hardware"),
    ("CVE-2026-1188", "High", 8.0, "Spring Framework Expression Injection Demo", "Application Framework")
]

def generate_safe_indicator(ind_type, idx):
    if ind_type == "IP ADDRESS":
        prefix = random.choice(SAFE_IPV4_PREFIXES)
        host = random.randint(1, 254)
        return f"{prefix[0]}.{prefix[1]}.{prefix[2]}.{host}"
    elif ind_type == "DOMAIN":
        sub = f"sub{random.randint(10, 99)}" if random.random() > 0.4 else "service"
        domain_base = random.choice(SAFE_DOMAINS)
        return f"{sub}.{domain_base}" if not domain_base.startswith("sub") else domain_base
    elif ind_type == "URL":
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_URL_PATHS)
        return f"https://{domain}{path}?session_id={random.randint(1000, 9999)}"
    elif ind_type == "FILE HASH":
        seed_str = f"safe-synthetic-sha256-demo-indicator-{idx}-{random.random()}"
        return hashlib.sha256(seed_str.encode()).hexdigest()
    elif ind_type == "EMAIL/SENDER DOMAIN":
        user = random.choice(["billing-verify", "hr-notices", "support-desk", "security-admin", "payroll-alert"])
        domain = random.choice(["example.com", "example.org", "example.net", "corporate-demo.invalid"])
        return f"{user}@{domain}"
    elif ind_type == "CVE ID":
        cve_pick = random.choice(SAMPLE_CVES)
        return cve_pick[0]
    return "192.0.2.1"

def generate_threat_dataset():
    records = []
    base_time = datetime(2026, 10, 1, 10, 0, 0)

    # Benchmark test threat as required by prompt
    bench_threat = {
        "threat_id": "THR-2026-001",
        "timestamp": (base_time - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "threat_name": "Synthetic Credential Phishing Campaign",
        "threat_category": "PHISHING",
        "indicator_type": "DOMAIN",
        "indicator_value": "login-check.invalid",
        "source_name": "Internal SOC",
        "source_reliability": "A – Highly Reliable",
        "confidence_score": 85,
        "severity": "HIGH",
        "risk_score": 78,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": (base_time - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
        "country_or_region_optional": "US",
        "description": "Indicator appears in multiple synthetic phishing observations targeting fake enterprise accounts.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Phishing: Spearphishing Link",
        "mitre_technique_id": "T1566.002",
        "cve_id_optional": "",
        "campaign_id": "CAMP-PHISH-01"
    }
    records.append(bench_threat)

    # Correlated partner record for THR-2026-001
    records.append({
        "threat_id": "THR-2026-002",
        "timestamp": (base_time - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "threat_name": "Correlated Synthetic C2 IP Observation",
        "threat_category": "PHISHING",
        "indicator_type": "IP ADDRESS",
        "indicator_value": "198.51.100.25",
        "source_name": "Internal SOC",
        "source_reliability": "A – Highly Reliable",
        "confidence_score": 80,
        "severity": "HIGH",
        "risk_score": 74,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=4)).strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": (base_time - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "country_or_region_optional": "US",
        "description": "Synthetic documentation IP tied to DNS records resolving for login-check.invalid.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Phishing: Spearphishing Link",
        "mitre_technique_id": "T1566.002",
        "cve_id_optional": "",
        "campaign_id": "CAMP-PHISH-01"
    })

    names_by_category = {
        "PHISHING": ["Spear-Phishing Credential Harvester", "Fake Invoice Redirector", "Corporate SSO Impersonation Portal", "Urgent Security Notification Lure"],
        "MALWARE": ["Generic Modular Loader Simulation", "InfoStealer Demo Artifact", "Encrypted Payload Delivery Simulation", "Memory Injection Testing Stub"],
        "RANSOMWARE": ["ShadowLocker Ransomware Activity", "Extortion Double-Dip Campaign", "Admin Share Lateral Probe", "VSS Shadow Copy Invalidation Stub"],
        "CREDENTIAL THREATS": ["Password Spraying against ADFS Demo", "Kerberoasting Probe Telemetry", "Synthetic Token Theft Activity", "Compromised Service Account Pattern"],
        "WEB THREATS": ["Cross-Site Scripting Injection Probe", "SQLi Pattern on Public Gateway", "Path Traversal Web Probe", "Server-Side Request Forgery Pattern"],
        "NETWORK THREATS": ["DNS Tunneling Exfiltration Signature", "Port 445 Scanning in Perimeter", "Anomalous SSH Bastion Brute Force", "ICMP Covert Beaconing Pattern"],
        "VULNERABILITY EXPOSURE": ["Edge Gateway Remote Buffer Trigger", "Unauthenticated Deserialization Scan", "Public Facing API Auth Bypass", "Legacy WebDAV Exploit Sweep"],
        "SOCIAL ENGINEERING": ["Executive Pretexting Call Campaign", "Fake IT Helpdesk Remote Access Lure", "Watering Hole Redirector Demo", "QR Code Phishing (Quishing) Test"],
        "DATA EXPOSURE": ["Misconfigured Cloud Bucket Scraping", "Sensitive API Endpoint Exposure", "Unencrypted Diagnostic Log Leak", "Exfiltration via Public Cloud Storage"],
        "ACCOUNT SECURITY": ["Impossible Travel Anomaly", "MFA Fatigue Authentication Surge", "Dormant Administrator Account Activation", "OAuth High-Privilege Consent Grant"]
    }

    for i in range(3, TOTAL_RECORDS + 1):
        cat = random.choice(THREAT_CATEGORIES)
        ind_type = random.choice(INDICATOR_TYPES)
        ind_val = generate_safe_indicator(ind_type, i)
        source, source_rel = random.choice(SOURCES)
        
        # Calculate realistic timestamps over the last 90 days
        days_ago = random.uniform(0.1, 90)
        seen_base = base_time - timedelta(days=days_ago)
        delta_hours = random.uniform(0, 120)
        first_seen = (seen_base - timedelta(hours=delta_hours)).strftime("%Y-%m-%d %H:%M:%S")
        last_seen = seen_base.strftime("%Y-%m-%d %H:%M:%S")
        record_time = last_seen

        # Severity & confidence distributions
        sev = random.choices(SEVERITIES, weights=[0.1, 0.25, 0.35, 0.20, 0.10])[0]
        if sev == "CRITICAL":
            risk = random.randint(81, 98)
            conf = random.randint(70, 95)
        elif sev == "HIGH":
            risk = random.randint(61, 80)
            conf = random.randint(60, 90)
        elif sev == "MEDIUM":
            risk = random.randint(41, 60)
            conf = random.randint(45, 85)
        elif sev == "LOW":
            risk = random.randint(21, 40)
            conf = random.randint(30, 80)
        else:
            risk = random.randint(5, 20)
            conf = random.randint(20, 70)

        # MITRE ATT&CK assignment if applicable
        mitre_tactic = ""
        mitre_technique = ""
        mitre_tech_id = ""
        if cat in MITRE_MAPPINGS and random.random() > 0.15:
            m_choice = random.choice(MITRE_MAPPINGS[cat])
            mitre_tactic = m_choice[0]
            mitre_technique = m_choice[1]
            mitre_tech_id = m_choice[2]

        # CVE assignment if vulnerability category or high severity
        cve_id = ""
        if cat == "VULNERABILITY EXPOSURE" or (ind_type == "CVE ID") or (random.random() < 0.08):
            cve_id = random.choice(SAMPLE_CVES)[0]
            if ind_type == "CVE ID":
                ind_val = cve_id

        # Campaign grouping for realistic correlation
        camp_id = ""
        if random.random() < 0.35:
            camp_num = random.randint(1, 25)
            camp_id = f"CAMP-DEFENSE-{camp_num:03d}"

        status = random.choices(STATUSES, weights=[0.25, 0.30, 0.25, 0.15, 0.05])[0]
        threat_name = f"{random.choice(names_by_category[cat])} #{i%100:02d}"
        desc = f"Synthetic telemetry record analyzing {cat.lower()} activity linked to defensive indicator {ind_val}."

        records.append({
            "threat_id": f"THR-2026-{i:04d}",
            "timestamp": record_time,
            "threat_name": threat_name,
            "threat_category": cat,
            "indicator_type": ind_type,
            "indicator_value": ind_val,
            "source_name": source,
            "source_reliability": source_rel,
            "confidence_score": conf,
            "severity": sev,
            "risk_score": risk,
            "status": status,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "country_or_region_optional": random.choice(COUNTRIES),
            "description": desc,
            "mitre_tactic_optional": mitre_tactic,
            "mitre_technique_optional": mitre_technique,
            "mitre_technique_id": mitre_tech_id,
            "cve_id_optional": cve_id,
            "campaign_id": camp_id
        })

    return records

def generate_vulnerability_dataset():
    cve_data = []
    base_date = datetime(2026, 1, 15)
    for idx, item in enumerate(SAMPLE_CVES, 1):
        cve_id, sev, cvss, desc, cat = item
        pub_date = (base_date + timedelta(days=idx * 22)).strftime("%Y-%m-%d")
        patch_avail = random.choice(["YES", "YES", "YES", "WORKAROUND_ONLY"])
        exploit_status = random.choice(["POC_PUBLIC_DEFENSIVE_ONLY", "NO_KNOWN_EXPLOIT", "THEORETICAL", "IN_THE_WILD_SIMULATED"])
        priority = int(cvss * 9.5) if patch_avail == "YES" else int(cvss * 10)
        cve_data.append({
            "vulnerability_id": f"VULN-2026-{idx:03d}",
            "cve_id": cve_id,
            "product_category": cat,
            "severity": sev,
            "cvss_score": cvss,
            "published_date": pub_date,
            "patch_available": patch_avail,
            "exploitation_status_demo": exploit_status,
            "priority_score": min(priority, 100),
            "description": f"{desc}. Strictly analyzed as synthetic vulnerability awareness telemetry."
        })
    return cve_data

if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    threat_records = generate_threat_dataset()
    threat_path = os.path.join(out_dir, "threat_intelligence_dataset.csv")
    if threat_records:
        with open(threat_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(threat_records[0].keys()))
            writer.writeheader()
            writer.writerows(threat_records)
    print(f"Generated {len(threat_records)} threat records at: {threat_path}")

    vuln_records = generate_vulnerability_dataset()
    vuln_path = os.path.join(out_dir, "vulnerabilities.csv")
    if vuln_records:
        with open(vuln_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(vuln_records[0].keys()))
            writer.writeheader()
            writer.writerows(vuln_records)
    print(f"Generated {len(vuln_records)} vulnerability records at: {vuln_path}")
