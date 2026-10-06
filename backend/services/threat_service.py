"""
Threat Intelligence Service Layer
Handles query filtering, sorting, statistics, indicator search, and CRUD.
"""

from typing import Dict, Any, List, Optional
import sqlite3
import pandas as pd
from backend.models.database import get_db_connection
from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.services.attack_mapper import analyze_attack_coverage
from backend.services.correlation_engine import correlate_threats, correlate_alerts

def get_threats(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    indicator_type: Optional[str] = None,
    status: Optional[str] = None,
    min_risk: Optional[float] = None,
    sort_by: str = "newest",
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    conn = get_db_connection()
    cur = conn.cursor()

    query = """
    SELECT t.threat_id, t.threat_name, t.category, t.description, t.severity,
           t.risk_score, t.confidence_score, t.status, t.first_seen, t.last_seen,
           t.country_or_region, t.campaign_id,
           i.indicator_type, i.indicator_value,
           s.source_name, s.reliability as source_reliability,
           am.tactic as mitre_tactic, am.technique as mitre_technique, am.technique_id as mitre_technique_id
    FROM THREATS t
    LEFT JOIN INDICATORS i ON t.threat_id = i.threat_id
    LEFT JOIN SOURCES s ON t.threat_id = s.threat_id
    LEFT JOIN ATTACK_MAPPINGS am ON t.threat_id = am.threat_id
    WHERE 1=1
    """
    params = []

    if severity and severity.upper() != "ALL":
        query += " AND UPPER(t.severity) = ?"
        params.append(severity.upper())
    if category and category.upper() != "ALL":
        query += " AND UPPER(t.category) = ?"
        params.append(category.upper())
    if status and status.upper() != "ALL":
        query += " AND UPPER(t.status) = ?"
        params.append(status.upper())
    if indicator_type and indicator_type.upper() != "ALL":
        query += " AND UPPER(i.indicator_type) = ?"
        params.append(indicator_type.upper())
    if min_risk is not None and min_risk > 0:
        query += " AND t.risk_score >= ?"
        params.append(min_risk)

    # Sorting
    if sort_by == "highest_risk":
        query += " ORDER BY t.risk_score DESC, t.last_seen DESC"
    elif sort_by == "highest_confidence":
        query += " ORDER BY t.confidence_score DESC, t.last_seen DESC"
    elif sort_by == "oldest":
        query += " ORDER BY t.last_seen ASC"
    else: # newest
        query += " ORDER BY t.last_seen DESC"

    # Count total matching
    count_query = f"SELECT COUNT(*) FROM ({query})"
    cur.execute(count_query, params)
    total_count = cur.fetchone()[0]

    query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "threats": rows
    }

def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT t.*, i.indicator_type, i.indicator_value,
           s.source_name, s.reliability as source_reliability,
           am.tactic as mitre_tactic, am.technique as mitre_technique, am.technique_id as mitre_technique_id
    FROM THREATS t
    LEFT JOIN INDICATORS i ON t.threat_id = i.threat_id
    LEFT JOIN SOURCES s ON t.threat_id = s.threat_id
    LEFT JOIN ATTACK_MAPPINGS am ON t.threat_id = am.threat_id
    WHERE t.threat_id = ?
    """, (threat_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    threat_data = dict(row)

    # Fetch notes
    cur.execute("SELECT * FROM ANALYST_NOTES WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,))
    threat_data["analyst_notes"] = [dict(n) for n in cur.fetchall()]

    # Fetch related alerts
    cur.execute("SELECT * FROM ALERTS WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,))
    threat_data["related_alerts"] = [dict(a) for a in cur.fetchall()]

    # Find related indicators via campaign or category
    cur.execute("""
    SELECT t.threat_id, t.threat_name, i.indicator_type, i.indicator_value, t.severity, t.risk_score
    FROM THREATS t
    JOIN INDICATORS i ON t.threat_id = i.threat_id
    WHERE (t.campaign_id = ? AND t.campaign_id != '') OR (t.category = ? AND t.threat_id != ?)
    LIMIT 6
    """, (threat_data.get("campaign_id", ""), threat_data.get("category", ""), threat_id))
    threat_data["related_indicators"] = [dict(r) for r in cur.fetchall()]

    # Timeline construct
    threat_data["timeline"] = [
        {"stage": "Observed", "timestamp": threat_data.get("first_seen"), "description": "First recorded observation in telemetry feed."},
        {"stage": "Validated & Normalized", "timestamp": threat_data.get("first_seen"), "description": "Syntax confirmed and indicator normalized."},
        {"stage": "Enriched & Scored", "timestamp": threat_data.get("first_seen"), "description": f"Risk assessed at {threat_data.get('risk_score')}/100."},
        {"stage": "Active Monitoring", "timestamp": threat_data.get("last_seen"), "description": f"Status updated to {threat_data.get('status')}."}
    ]

    conn.close()
    return threat_data

def search_indicator_service(query_str: str) -> Dict[str, Any]:
    validation = validate_indicator(query_str)
    conn = get_db_connection()
    cur = conn.cursor()

    # Retrieve all threat records to perform enrichment
    cur.execute("""
    SELECT t.threat_id, t.threat_name, t.category as threat_category, t.severity, t.risk_score,
           t.confidence_score, t.status, t.first_seen, t.last_seen, t.campaign_id,
           i.indicator_type, i.indicator_value, s.source_name, am.tactic as mitre_tactic_optional,
           am.technique as mitre_technique_optional
    FROM THREATS t
    LEFT JOIN INDICATORS i ON t.threat_id = i.threat_id
    LEFT JOIN SOURCES s ON t.threat_id = s.threat_id
    LEFT JOIN ATTACK_MAPPINGS am ON t.threat_id = am.threat_id
    """)
    records = [dict(r) for r in cur.fetchall()]
    conn.close()

    enrichment = enrich_indicator(validation["normalized_value"], validation["indicator_type"], records)
    enrichment["validation"] = validation
    return enrichment

def get_dashboard_statistics() -> Dict[str, Any]:
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM THREATS")
    total_threats = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM THREATS WHERE severity = 'CRITICAL'")
    critical_threats = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM THREATS WHERE severity = 'HIGH'")
    high_threats = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT indicator_value) FROM INDICATORS")
    active_indicators = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM ALERTS WHERE status IN ('NEW', 'INVESTIGATING')")
    open_investigations = cur.fetchone()[0]

    cur.execute("SELECT AVG(confidence_score) FROM THREATS")
    avg_conf = round(cur.fetchone()[0] or 0, 1)

    cur.execute("SELECT COUNT(*) FROM VULNERABILITIES")
    vulns_tracked = cur.fetchone()[0]

    # Category breakdown
    cur.execute("SELECT category, COUNT(*) as cnt FROM THREATS GROUP BY category ORDER BY cnt DESC")
    by_category = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

    # Severity breakdown
    cur.execute("SELECT severity, COUNT(*) as cnt FROM THREATS GROUP BY severity")
    by_severity = [{"severity": r[0], "count": r[1]} for r in cur.fetchall()]

    # Status breakdown
    cur.execute("SELECT status, COUNT(*) as cnt FROM THREATS GROUP BY status")
    by_status = [{"status": r[0], "count": r[1]} for r in cur.fetchall()]

    # IOC Type breakdown
    cur.execute("SELECT indicator_type, COUNT(*) as cnt FROM INDICATORS GROUP BY indicator_type ORDER BY cnt DESC")
    by_ioc_type = [{"indicator_type": r[0], "count": r[1]} for r in cur.fetchall()]

    # Vulnerabilities by severity
    cur.execute("SELECT severity, COUNT(*) as cnt FROM VULNERABILITIES GROUP BY severity")
    vulns_by_sev = [{"severity": r[0], "count": r[1]} for r in cur.fetchall()]

    # Recent threats
    cur.execute("""
    SELECT t.threat_id, t.threat_name, t.category, t.severity, t.risk_score, t.confidence_score,
           t.status, t.last_seen, i.indicator_type, i.indicator_value
    FROM THREATS t
    LEFT JOIN INDICATORS i ON t.threat_id = i.threat_id
    ORDER BY t.last_seen DESC LIMIT 10
    """)
    recent = [dict(r) for r in cur.fetchall()]

    # ATT&CK Summary
    cur.execute("SELECT tactic as mitre_tactic_optional, technique as mitre_technique_optional, technique_id as mitre_technique_id FROM ATTACK_MAPPINGS")
    attack_rows = [dict(r) for r in cur.fetchall()]
    attack_summary = analyze_attack_coverage(attack_rows)

    conn.close()

    return {
        "cards": {
            "total_threats": total_threats,
            "critical_threats": critical_threats,
            "high_threats": high_threats,
            "active_indicators": active_indicators,
            "open_investigations": open_investigations,
            "average_confidence": avg_conf,
            "vulnerabilities_tracked": vulns_tracked
        },
        "by_category": by_category,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_ioc_type": by_ioc_type,
        "vulns_by_severity": vulns_by_sev,
        "attack_summary": attack_summary,
        "recent_threats": recent
    }

def add_analyst_note_service(threat_id: str, note_text: str, author: str = "SOC Analyst (Tier-1)") -> Dict[str, Any]:
    from datetime import datetime
    conn = get_db_connection()
    cur = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
    INSERT INTO ANALYST_NOTES (threat_id, author, note, created_at)
    VALUES (?, ?, ?, ?)
    """, (threat_id, author, note_text, now_str))
    conn.commit()
    conn.close()
    return {"success": True, "threat_id": threat_id, "note": note_text, "created_at": now_str}
