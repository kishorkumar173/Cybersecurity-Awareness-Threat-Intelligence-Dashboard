"""
MITRE ATT&CK Mapping & Analytics Engine
Maps defensive threat records to ATT&CK tactics and techniques.
Provides analytical breakdowns for top tactics, techniques, and frequency.
"""

from typing import List, Dict, Any
from collections import Counter

ATTACK_TACTIC_DESCRIPTIONS = {
    "Initial Access": "Techniques used by adversaries to gain an initial foothold within a network or endpoint.",
    "Execution": "Techniques that result in adversary-controlled code running on a local or remote system.",
    "Persistence": "Techniques adversaries use to maintain access to systems across restarts or credential changes.",
    "Privilege Escalation": "Techniques used to gain higher-level permissions on a system or network.",
    "Defense Evasion": "Techniques used to avoid detection by defensive tools and security controls.",
    "Credential Access": "Techniques for stealing credentials like passwords, hashes, and session tokens.",
    "Discovery": "Techniques used to gain knowledge about the system and internal network topology.",
    "Lateral Movement": "Techniques adversaries use to enter and control remote systems on a network.",
    "Collection": "Techniques used to gather data of interest to the adversary's goals.",
    "Command and Control": "Techniques used to communicate with systems under their control within a victim network.",
    "Exfiltration": "Techniques used to steal or duplicate data from target systems.",
    "Impact": "Techniques used to disrupt, corrupt, or destroy systems and data (e.g., encryption in ransomware)."
}

def analyze_attack_coverage(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes tactic and technique distributions across threat intelligence records.
    """
    tactics = []
    techniques = []
    tech_details = {}

    for r in records:
        tactic = r.get("mitre_tactic_optional")
        tech = r.get("mitre_technique_optional")
        tech_id = r.get("mitre_technique_id")

        if tactic:
            tactics.append(tactic)
        if tech:
            techniques.append(tech)
            if tech not in tech_details:
                tech_details[tech] = {
                    "technique_name": tech,
                    "technique_id": tech_id or "N/A",
                    "tactic": tactic,
                    "tactic_description": ATTACK_TACTIC_DESCRIPTIONS.get(tactic, "Adversary tactic"),
                    "count": 0
                }
            tech_details[tech]["count"] += 1

    tactic_counts = Counter(tactics)
    technique_counts = Counter(techniques)

    top_tactics = [{"tactic": k, "count": v} for k, v in tactic_counts.most_common(8)]
    top_techniques = [
        {
            "technique": k, 
            "technique_id": tech_details[k]["technique_id"],
            "tactic": tech_details[k]["tactic"],
            "count": v
        } 
        for k, v in technique_counts.most_common(10)
    ]

    return {
        "top_tactics": top_tactics,
        "top_techniques": top_techniques,
        "total_mapped_records": len(tactics),
        "unmapped_records": len(records) - len(tactics),
        "coverage_rate": round((len(tactics) / len(records) * 100) if records else 0, 1)
    }
