"""
Database Schema & Initialization
SQLite relational store managing:
- THREATS
- INDICATORS
- SOURCES
- ATTACK_MAPPINGS
- VULNERABILITIES
- ALERTS
- ANALYST_NOTES
- AWARENESS_MODULES
- QUIZ_RESULTS
"""

import sqlite3
import os
import pandas as pd

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "data", "cyber_threat_intel.db")
DB_PATH = os.path.abspath(DB_PATH)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db_connection()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS THREATS (
        threat_id TEXT PRIMARY KEY,
        threat_name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        confidence_score REAL NOT NULL,
        status TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        country_or_region TEXT,
        campaign_id TEXT
    );

    CREATE TABLE IF NOT EXISTS INDICATORS (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        FOREIGN KEY(threat_id) REFERENCES THREATS(threat_id)
    );

    CREATE TABLE IF NOT EXISTS SOURCES (
        source_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        source_name TEXT NOT NULL,
        reliability TEXT NOT NULL,
        FOREIGN KEY(threat_id) REFERENCES THREATS(threat_id)
    );

    CREATE TABLE IF NOT EXISTS ATTACK_MAPPINGS (
        mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        tactic TEXT NOT NULL,
        technique TEXT NOT NULL,
        technique_id TEXT,
        FOREIGN KEY(threat_id) REFERENCES THREATS(threat_id)
    );

    CREATE TABLE IF NOT EXISTS VULNERABILITIES (
        vulnerability_id TEXT PRIMARY KEY,
        cve_id TEXT NOT NULL UNIQUE,
        product_category TEXT,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        patch_available TEXT,
        priority_score REAL,
        exploitation_status TEXT,
        description TEXT,
        published_date TEXT
    );

    CREATE TABLE IF NOT EXISTS ALERTS (
        alert_id TEXT PRIMARY KEY,
        threat_id TEXT,
        alert_type TEXT,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        confidence_score REAL,
        description TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(threat_id) REFERENCES THREATS(threat_id)
    );

    CREATE TABLE IF NOT EXISTS ANALYST_NOTES (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        author TEXT DEFAULT 'SOC Analyst (Tier-1)',
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(threat_id) REFERENCES THREATS(threat_id)
    );

    CREATE TABLE IF NOT EXISTS AWARENESS_MODULES (
        module_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        summary TEXT,
        content_json TEXT
    );

    CREATE TABLE IF NOT EXISTS QUIZ_RESULTS (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        anonymous_user_id TEXT DEFAULT 'User-Demo',
        overall_score REAL NOT NULL,
        category_breakdown_json TEXT,
        recommendations_json TEXT,
        created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_indicators_value ON INDICATORS(indicator_value);
    CREATE INDEX IF NOT EXISTS idx_threats_category ON THREATS(category);
    CREATE INDEX IF NOT EXISTS idx_threats_severity ON THREATS(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON ALERTS(status);
    """)

    conn.commit()

    # Check if threats table needs seed from CSV
    cur.execute("SELECT COUNT(*) FROM THREATS")
    cnt = cur.fetchone()[0]

    csv_path = os.path.join(os.path.dirname(DB_PATH), "threat_intelligence_dataset.csv")
    if (cnt == 0 or force_reseed) and os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        for _, row in df.iterrows():
            tid = str(row["threat_id"])
            cur.execute("""
                INSERT OR REPLACE INTO THREATS 
                (threat_id, threat_name, category, description, severity, risk_score, confidence_score, status, first_seen, last_seen, country_or_region, campaign_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tid,
                str(row["threat_name"]),
                str(row["threat_category"]),
                str(row["description"]),
                str(row["severity"]),
                float(row["risk_score"]),
                float(row["confidence_score"]),
                str(row["status"]),
                str(row["first_seen"]),
                str(row["last_seen"]),
                str(row.get("country_or_region_optional", "Global")),
                str(row.get("campaign_id", ""))
            ))

            cur.execute("""
                INSERT INTO INDICATORS (threat_id, indicator_type, indicator_value, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (
                tid,
                str(row["indicator_type"]),
                str(row["indicator_value"]),
                str(row["first_seen"]),
                str(row["last_seen"])
            ))

            cur.execute("""
                INSERT INTO SOURCES (threat_id, source_name, reliability)
                VALUES (?, ?, ?)
            """, (
                tid,
                str(row["source_name"]),
                str(row.get("source_reliability", "B – Usually Reliable"))
            ))

            if pd.notna(row.get("mitre_tactic_optional")) and str(row.get("mitre_tactic_optional")).strip():
                cur.execute("""
                    INSERT INTO ATTACK_MAPPINGS (threat_id, tactic, technique, technique_id)
                    VALUES (?, ?, ?, ?)
                """, (
                    tid,
                    str(row["mitre_tactic_optional"]),
                    str(row["mitre_technique_optional"]),
                    str(row.get("mitre_technique_id", ""))
                ))

            # Generate alerts for high/critical threats
            if float(row["risk_score"]) >= 70 or str(row["severity"]) in ["HIGH", "CRITICAL"]:
                alt_id = f"ALT-{tid.replace('THR-', '')}"
                cur.execute("""
                    INSERT OR REPLACE INTO ALERTS
                    (alert_id, threat_id, alert_type, severity, risk_score, confidence_score, description, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alt_id,
                    tid,
                    f"{row['threat_category']}_ALERT",
                    str(row["severity"]),
                    float(row["risk_score"]),
                    float(row["confidence_score"]),
                    f"Prioritized defensive alert: {row['threat_name']} with risk {row['risk_score']}/100.",
                    "NEW" if float(row["risk_score"]) >= 80 else "INVESTIGATING",
                    str(row["last_seen"])
                ))

        conn.commit()
        print(f"Database seeded with {len(df)} threat records.")

    # Seed vulnerabilities
    vuln_csv = os.path.join(os.path.dirname(DB_PATH), "vulnerabilities.csv")
    cur.execute("SELECT COUNT(*) FROM VULNERABILITIES")
    vcnt = cur.fetchone()[0]
    if (vcnt == 0 or force_reseed) and os.path.exists(vuln_csv):
        vdf = pd.read_csv(vuln_csv)
        for _, row in vdf.iterrows():
            cur.execute("""
                INSERT OR REPLACE INTO VULNERABILITIES
                (vulnerability_id, cve_id, product_category, severity, cvss_score, patch_available, priority_score, exploitation_status, description, published_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(row["vulnerability_id"]),
                str(row["cve_id"]),
                str(row["product_category"]),
                str(row["severity"]),
                float(row["cvss_score"]),
                str(row["patch_available"]),
                float(row["priority_score"]),
                str(row["exploitation_status_demo"]),
                str(row["description"]),
                str(row["published_date"])
            ))
        conn.commit()
        print(f"Database seeded with {len(vdf)} vulnerability records.")

    # Seed initial analyst note for benchmark threat
    cur.execute("SELECT COUNT(*) FROM ANALYST_NOTES WHERE threat_id = 'THR-2026-001'")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO ANALYST_NOTES (threat_id, author, note, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            "THR-2026-001",
            "Lead SOC Analyst (Tier-2)",
            "Indicator login-check.invalid appears in multiple synthetic phishing observations. Correlated with synthetic IP 198.51.100.25. Defensive monitoring recommended.",
            "2026-10-05 14:30:00"
        ))
        conn.commit()

    conn.close()

if __name__ == "__main__":
    init_db(force_reseed=True)
