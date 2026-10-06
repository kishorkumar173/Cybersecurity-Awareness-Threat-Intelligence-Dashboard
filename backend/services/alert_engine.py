"""
Security Alert Engine
Generates prioritized analyst alerts when indicators or events surpass 
defined risk, confidence, or vulnerability severity thresholds.
"""

from typing import Dict, Any, List
from datetime import datetime

def generate_threat_alert(threat_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates whether a threat record warrants an active SOC alert.
    Triggers when risk_score >= 65 or severity is CRITICAL / HIGH.
    """
    risk = float(threat_record.get("risk_score", 0))
    conf = float(threat_record.get("confidence_score", 0))
    sev = threat_record.get("severity", "LOW")

    if risk >= 65 or sev in ["CRITICAL", "HIGH"]:
        alert_type = f"{threat_record.get('threat_category', 'THREAT')}_ESCALATION"
        alert_id = f"ALT-{threat_record.get('threat_id', 'GEN').replace('THR-', '')}"
        
        return {
            "alert_id": alert_id,
            "threat_id": threat_record.get("threat_id"),
            "timestamp": threat_record.get("last_seen", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "alert_type": alert_type,
            "severity": sev,
            "risk_score": risk,
            "confidence_score": conf,
            "indicator_value": threat_record.get("indicator_value"),
            "description": f"Elevated threat detected: {threat_record.get('threat_name')} with risk {risk}/100 and confidence {conf}%.",
            "status": "NEW" if risk >= 80 else "INVESTIGATING"
        }
    return None

def evaluate_all_alerts(threat_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generates alerts across a batch of threat records.
    """
    alerts = []
    for r in threat_records:
        al = generate_threat_alert(r)
        if al:
            alerts.append(al)
    return alerts
