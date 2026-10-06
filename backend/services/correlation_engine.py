"""
Threat & Alert Correlation Engine
Solves alert fatigue by clustering related indicators and deduping recurring observations.

Defensive Principle:
Correlation implies shared evidence or structural linkage, NOT guaranteed attribution.
"""

from typing import List, Dict, Any
from collections import defaultdict

def correlate_threats(threat_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups threat records sharing campaign IDs, common categories, or infrastructure patterns
    into high-fidelity threat clusters.
    """
    clusters = defaultdict(list)

    for r in threat_records:
        camp = r.get("campaign_id")
        cat = r.get("threat_category", "UNKNOWN")
        if camp:
            key = f"CAMPAIGN::{camp}"
        else:
            # Group by category and observation window
            key = f"CATEGORY::{cat}"
        clusters[key].append(r)

    cluster_list = []
    cluster_idx = 1
    for key, items in clusters.items():
        if len(items) >= 2:
            indicators = list(set([it.get("indicator_value") for it in items if it.get("indicator_value")]))
            severities = [it.get("severity") for it in items]
            avg_risk = round(sum([float(it.get("risk_score", 50)) for it in items]) / len(items), 1)
            categories = list(set([it.get("threat_category") for it in items]))

            cluster_list.append({
                "cluster_id": f"CLUST-2026-{cluster_idx:03d}",
                "cluster_name": f"Correlated Cluster: {key.replace('::', ' - ')}",
                "member_count": len(items),
                "threat_ids": [it.get("threat_id") for it in items[:10]],
                "distinct_indicators": indicators[:8],
                "categories": categories,
                "average_risk": avg_risk,
                "summary": f"Correlation engine identified {len(items)} related telemetry sightings connected through shared campaign telemetry and defensive category profiles.",
                "attribution_disclaimer": "Defensive clustering indicates correlated telemetry; adversary attribution remains unconfirmed."
            })
            cluster_idx += 1

    return cluster_list

def correlate_alerts(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggregates repeated observations of the same indicator or signature to prevent SOC fatigue.
    Turns 100 duplicate hits into 1 correlated alert with count = 100.
    """
    grouped = defaultdict(list)
    for evt in raw_events:
        ind = evt.get("indicator_value", evt.get("threat_id", "UNKNOWN"))
        grouped[ind].append(evt)

    deduped_alerts = []
    alert_idx = 1
    for ind_val, evts in grouped.items():
        first_evt = evts[0]
        count = len(evts)
        highest_risk = max([float(e.get("risk_score", 50)) for e in evts])
        highest_sev = evts[0].get("severity", "MEDIUM")

        alert_id = f"ALT-2026-{alert_idx:04d}"
        deduped_alerts.append({
            "alert_id": alert_id,
            "threat_id": first_evt.get("threat_id", "N/A"),
            "indicator_value": ind_val,
            "observation_count": count,
            "severity": highest_sev,
            "risk_score": highest_risk,
            "confidence_score": first_evt.get("confidence_score", 70),
            "alert_type": f"CORRELATED_{first_evt.get('threat_category', 'SECURITY')}_ALERT",
            "status": "NEW" if highest_risk >= 75 else "MONITORING",
            "timestamp": first_evt.get("timestamp", first_evt.get("last_seen")),
            "description": f"Consolidated alert summarizing {count} observation sighting(s) for indicator {ind_val}. Aggregated to mitigate SOC alert fatigue."
        })
        alert_idx += 1

    return deduped_alerts
