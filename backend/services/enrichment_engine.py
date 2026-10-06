"""
Threat Enrichment Engine
Safe, offline-first threat indicator enrichment using local synthetic intelligence.
Enriches indicators with historical context, category relations, sightings, 
source reliability, MITRE ATT&CK concepts, and defensive recommendations.
Does NOT initiate external network probes or live connections.
"""

from typing import Dict, Any, List

def enrich_indicator(
    indicator_val: str,
    indicator_type: str,
    dataset_records: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Enriches a validated indicator against local telemetry records.
    Returns aggregated defensive profile and context.
    """
    val_norm = indicator_val.strip().lower()
    
    # Filter matching sightings in local threat intelligence repository
    matches = [
        r for r in dataset_records 
        if str(r.get("indicator_value", "")).strip().lower() == val_norm or
           str(r.get("cve_id_optional", "")).strip().upper() == indicator_val.strip().upper()
    ]

    is_known = len(matches) > 0
    obs_count = len(matches)

    if is_known:
        # Aggregate categories and tactics
        categories = list(set([m.get("threat_category") for m in matches if m.get("threat_category")]))
        tactics = list(set([m.get("mitre_tactic_optional") for m in matches if m.get("mitre_tactic_optional")]))
        techniques = list(set([m.get("mitre_technique_optional") for m in matches if m.get("mitre_technique_optional")]))
        severities = [m.get("severity") for m in matches if m.get("severity")]
        
        # Determine highest severity
        sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
        top_sev = max(severities, key=lambda s: sev_rank.get(s, 0)) if severities else "INFORMATIONAL"
        
        avg_confidence = round(sum([float(m.get("confidence_score", 50)) for m in matches]) / len(matches), 1)
        avg_risk = round(sum([float(m.get("risk_score", 50)) for m in matches]) / len(matches), 1)
        
        first_seen = min([m.get("first_seen", "") for m in matches if m.get("first_seen")])
        last_seen = max([m.get("last_seen", "") for m in matches if m.get("last_seen")])
        sources = list(set([m.get("source_name") for m in matches if m.get("source_name")]))
        campaigns = list(set([m.get("campaign_id") for m in matches if m.get("campaign_id")]))
        status = matches[0].get("status", "MONITORING")
        top_threat_id = matches[0].get("threat_id", "")
    else:
        categories = ["UNCLASSIFIED_DEFENSIVE_LOOKUP"]
        tactics = []
        techniques = []
        top_sev = "INFORMATIONAL"
        avg_confidence = 35.0
        avg_risk = 15.0
        first_seen = "Not observed in local intelligence feed"
        last_seen = "Not observed in local intelligence feed"
        sources = ["Internal Query Engine"]
        campaigns = []
        status = "NO_PRIOR_SIGHTING"
        top_threat_id = "N/A"

    # Contextual defensive recommendations
    defensive_actions = [
        "Query internal SIEM and proxy logs for passive sighting history (no direct outbound connection).",
        "Verify if any perimeter sensors or DNS resolvers flagged queries for this artifact.",
        "Check endpoint detection and response (EDR) telemetry for matching hash or process execution artifacts.",
        "Ensure targeted user groups receive awareness guidance on relevant lure types.",
        "Maintain indicator in passive monitoring list; verify potential false positive risk."
    ]

    return {
        "indicator_value": indicator_val,
        "indicator_type": indicator_type,
        "is_known_in_dataset": is_known,
        "observation_count": obs_count,
        "top_threat_id": top_threat_id,
        "severity": top_sev,
        "risk_score": avg_risk,
        "confidence_score": avg_confidence,
        "status": status,
        "associated_categories": categories,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sources": sources,
        "associated_campaigns": campaigns,
        "defensive_recommendations": defensive_actions,
        "analyst_notes": f"Defensive lookup concluded. {obs_count} associated record(s) cataloged in local intelligence repository."
    }
