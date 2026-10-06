"""
Defensive Threat Risk & Confidence Scoring Engine

Formulates transparent, multi-factor calculations:
1. Threat Risk (0-100):
   - Severity: 30%
   - Confidence: 25%
   - Recency: 15%
   - Observation Count: 10%
   - Source Reliability: 10%
   - Context / Correlation: 10%

2. Confidence Score (0-100):
   - Measures analytical certainty in the quality and corroborated evidence of the intel,
     independent of potential impact.

3. Vulnerability Prioritization:
   - Combines CVSS + Asset Criticality + Internet Exposure + Exploit Availability.
"""

from datetime import datetime

SEVERITY_WEIGHTS = {
    "INFORMATIONAL": 15,
    "LOW": 30,
    "MEDIUM": 55,
    "HIGH": 80,
    "CRITICAL": 100
}

SOURCE_RELIABILITY_SCORES = {
    "A – Highly Reliable": 100,
    "B – Usually Reliable": 80,
    "C – Fairly Reliable": 60,
    "D – Reliability Unknown": 35
}

def calculate_threat_risk(
    severity: str,
    confidence: float,
    last_seen_str: str,
    observation_count: int = 1,
    source_reliability: str = "B – Usually Reliable",
    has_correlation: bool = False
) -> dict:
    """
    Computes weighted defensive risk score (0-100) and severity classification.
    """
    # 1. Severity component (30%)
    sev_val = SEVERITY_WEIGHTS.get(severity.upper(), 50)
    w_sev = sev_val * 0.30

    # 2. Confidence component (25%)
    conf_clamped = max(0, min(100, float(confidence)))
    w_conf = conf_clamped * 0.25

    # 3. Recency component (15%)
    days_old = 15
    try:
        last_dt = datetime.strptime(last_seen_str[:19], "%Y-%m-%d %H:%M:%S")
        days_old = (datetime.now() - last_dt).total_seconds() / 86400.0
    except Exception:
        pass
    
    if days_old <= 3:
        recency_val = 100
    elif days_old <= 7:
        recency_val = 80
    elif days_old <= 30:
        recency_val = 55
    elif days_old <= 90:
        recency_val = 30
    else:
        recency_val = 15
    w_recency = recency_val * 0.15

    # 4. Observation count (10%)
    obs_val = min(100, 20 + (observation_count * 15))
    w_obs = obs_val * 0.10

    # 5. Source Reliability (10%)
    src_val = SOURCE_RELIABILITY_SCORES.get(source_reliability, 50)
    w_src = src_val * 0.10

    # 6. Context / Correlation (10%)
    w_corr = (95 if has_correlation else 40) * 0.10

    # Total score calculation
    raw_risk = w_sev + w_conf + w_recency + w_obs + w_src + w_corr
    risk_score = int(round(max(0, min(100, raw_risk))))

    # Risk classification bands
    if risk_score <= 20:
        classification = "INFORMATIONAL"
    elif risk_score <= 40:
        classification = "LOW"
    elif risk_score <= 60:
        classification = "MEDIUM"
    elif risk_score <= 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"

    return {
        "risk_score": risk_score,
        "classification": classification,
        "breakdown": {
            "severity_weight": round(w_sev, 1),
            "confidence_weight": round(w_conf, 1),
            "recency_weight": round(w_recency, 1),
            "observations_weight": round(w_obs, 1),
            "source_weight": round(w_src, 1),
            "correlation_weight": round(w_corr, 1)
        },
        "interpretation": f"Risk assessed at {risk_score}/100 based on corroborated multi-source factors. High risk indicates elevated defensive priority, not confirmed compromise."
    }

def calculate_vulnerability_priority(
    cvss_score: float,
    asset_criticality: str = "HIGH",
    is_internet_facing: bool = True,
    known_exploitation: str = "POC_PUBLIC_DEFENSIVE_ONLY",
    patch_available: str = "YES"
) -> dict:
    """
    Contextual vulnerability prioritization:
    CVSS + Asset Criticality + Internet Exposure + Exploitation Evidence + Patch Availability
    """
    base = cvss_score * 10  # 0 - 100

    crit_multiplier = {
        "MISSION_CRITICAL": 1.25,
        "HIGH": 1.10,
        "MEDIUM": 0.90,
        "LOW / TEST": 0.65
    }.get(asset_criticality.upper(), 1.0)

    exposure_multiplier = 1.20 if is_internet_facing else 0.80

    exploit_factor = {
        "IN_THE_WILD_SIMULATED": 20,
        "POC_PUBLIC_DEFENSIVE_ONLY": 10,
        "THEORETICAL": 0,
        "NO_KNOWN_EXPLOIT": -10
    }.get(known_exploitation, 0)

    raw_priority = (base * crit_multiplier * exposure_multiplier) + exploit_factor
    priority_score = int(round(max(0, min(100, raw_priority))))

    if priority_score >= 85:
        urgency = "EMERGENCY_PATCH_24H"
    elif priority_score >= 70:
        urgency = "PRIORITY_PATCH_7D"
    elif priority_score >= 50:
        urgency = "STANDARD_CYCLE_30D"
    else:
        urgency = "ROUTINE_BACKLOG"

    return {
        "priority_score": priority_score,
        "urgency_tier": urgency,
        "patch_status": patch_available,
        "explanation": f"CVSS of {cvss_score} adjusted for asset criticality ({asset_criticality}), exposure ({'Internet-facing' if is_internet_facing else 'Internal'}), and exploit telemetry."
    }
