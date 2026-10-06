"""
Automated Test Suite for Cybersecurity Dashboard Project
Covers 37 targeted defensive test scenarios validating:
- IOC formats (IPv4, IPv6, Domains, URLs, Hashes, CVEs)
- Threat creation, risk & confidence calculations
- Source reliability scoring
- Indicator enrichment & search
- Correlation & deduplication
- Alert generation & status updates
- Analyst notes & ATT&CK mapping
- Vulnerability prioritization
- REST API validation & database persistence
- Awareness modules & quiz scoring
"""

import pytest
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk, calculate_vulnerability_priority
from backend.services.enrichment_engine import enrich_indicator
from backend.services.correlation_engine import correlate_threats, correlate_alerts
from backend.services.alert_engine import generate_threat_alert
from backend.services.attack_mapper import analyze_attack_coverage
from backend.models.database import get_db_connection, init_db
from backend.services.threat_service import get_threats, get_threat_by_id, search_indicator_service

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    init_db(force_reseed=False)

# ----------------- 1. IOC VALIDATOR TESTS (1 - 11) -----------------
def test_01_valid_ipv4_rfc5737():
    res = validate_indicator("198.51.100.25")
    assert res["valid"] is True
    assert res["indicator_type"] == "IP ADDRESS"
    assert "RFC 5737" in res["validation_notes"]

def test_02_invalid_ipv4():
    res = validate_indicator("999.300.1.1")
    assert res["valid"] is False
    assert res["indicator_type"] == "INVALID / UNKNOWN"

def test_03_valid_ipv6():
    res = validate_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res["valid"] is True
    assert "IPv6" in res["indicator_type"]

def test_04_valid_domain():
    res = validate_indicator("login-check.invalid")
    assert res["valid"] is True
    assert res["indicator_type"] == "DOMAIN"
    assert res["normalized_value"] == "login-check.invalid"

def test_05_invalid_domain():
    res = validate_indicator("invalid..domain..")
    assert res["valid"] is False

def test_06_valid_url():
    res = validate_indicator("https://auth-gateway.example.com/verify?id=123")
    assert res["valid"] is True
    assert res["indicator_type"] == "URL"

def test_07_valid_md5_hash():
    res = validate_indicator("d41d8cd98f00b204e9800998ecf8427e")
    assert res["valid"] is True
    assert "MD5" in res["indicator_type"]

def test_08_valid_sha1_hash():
    res = validate_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert res["valid"] is True
    assert "SHA-1" in res["indicator_type"]

def test_09_valid_sha256_hash():
    dummy_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = validate_indicator(dummy_sha256)
    assert res["valid"] is True
    assert "SHA-256" in res["indicator_type"]

def test_10_valid_cve_format():
    res = validate_indicator("CVE-2026-1042")
    assert res["valid"] is True
    assert res["indicator_type"] == "CVE ID"
    assert res["normalized_value"] == "CVE-2026-1042"

def test_11_invalid_cve_format():
    res = validate_indicator("CVE-INVALID-FORMAT")
    assert res["valid"] is False

# ----------------- 2. RISK & CONFIDENCE SCORING (12 - 16) -----------------
def test_12_risk_calculation_critical():
    res = calculate_threat_risk("CRITICAL", 90.0, "2026-10-06 12:00:00", observation_count=5, has_correlation=True)
    assert 80 <= res["risk_score"] <= 100
    assert res["classification"] == "CRITICAL"

def test_13_risk_calculation_low():
    res = calculate_threat_risk("LOW", 30.0, "2026-05-01 12:00:00", observation_count=1, has_correlation=False)
    assert res["risk_score"] <= 45
    assert res["classification"] in ["LOW", "INFORMATIONAL"]

def test_14_confidence_clamping():
    res = calculate_threat_risk("MEDIUM", 150.0, "2026-10-01 12:00:00")
    assert res["breakdown"]["confidence_weight"] <= 25.0

def test_15_source_reliability_weight():
    high_src = calculate_threat_risk("HIGH", 70.0, "2026-10-01 12:00:00", source_reliability="A – Highly Reliable")
    unknown_src = calculate_threat_risk("HIGH", 70.0, "2026-10-01 12:00:00", source_reliability="D – Reliability Unknown")
    assert high_src["risk_score"] >= unknown_src["risk_score"]

def test_16_vulnerability_prioritization_internet_facing():
    p_facing = calculate_vulnerability_priority(9.8, asset_criticality="MISSION_CRITICAL", is_internet_facing=True)
    p_isolated = calculate_vulnerability_priority(9.8, asset_criticality="LOW / TEST", is_internet_facing=False)
    assert p_facing["priority_score"] > p_isolated["priority_score"]
    assert p_facing["urgency_tier"] == "EMERGENCY_PATCH_24H"

# ----------------- 3. ENRICHMENT & SEARCH (17 - 19) -----------------
def test_17_enrichment_known_benchmark_indicator():
    records = [{
        "threat_id": "THR-2026-001", "threat_category": "PHISHING", "indicator_value": "login-check.invalid",
        "severity": "HIGH", "risk_score": 78, "confidence_score": 85, "first_seen": "2026-10-01 10:00:00",
        "last_seen": "2026-10-06 12:00:00", "source_name": "Internal SOC", "campaign_id": "CAMP-01"
    }]
    enrich = enrich_indicator("login-check.invalid", "DOMAIN", records)
    assert enrich["is_known_in_dataset"] is True
    assert enrich["observation_count"] == 1
    assert "PHISHING" in enrich["associated_categories"]

def test_18_enrichment_unknown_indicator():
    enrich = enrich_indicator("unknown-test-domain.invalid", "DOMAIN", [])
    assert enrich["is_known_in_dataset"] is False
    assert enrich["observation_count"] == 0
    assert enrich["status"] == "NO_PRIOR_SIGHTING"

def test_19_indicator_search_service():
    res = search_indicator_service("198.51.100.25")
    assert res["validation"]["valid"] is True
    assert res["is_known_in_dataset"] is True

# ----------------- 4. CORRELATION & ALERTING (20 - 24) -----------------
def test_20_threat_clustering():
    records = [
        {"threat_id": "T1", "threat_category": "PHISHING", "campaign_id": "CAMP-DEMO", "indicator_value": "198.51.100.1", "risk_score": 75, "severity": "HIGH"},
        {"threat_id": "T2", "threat_category": "PHISHING", "campaign_id": "CAMP-DEMO", "indicator_value": "login.invalid", "risk_score": 80, "severity": "HIGH"}
    ]
    clusters = correlate_threats(records)
    assert len(clusters) == 1
    assert clusters[0]["member_count"] == 2
    assert "adversary attribution remains unconfirmed" in clusters[0]["attribution_disclaimer"].lower()

def test_21_alert_deduplication():
    events = [
        {"threat_id": "T1", "indicator_value": "198.51.100.1", "risk_score": 80, "severity": "HIGH", "timestamp": "2026-10-06 10:00:00"},
        {"threat_id": "T1", "indicator_value": "198.51.100.1", "risk_score": 80, "severity": "HIGH", "timestamp": "2026-10-06 10:01:00"},
        {"threat_id": "T1", "indicator_value": "198.51.100.1", "risk_score": 80, "severity": "HIGH", "timestamp": "2026-10-06 10:02:00"}
    ]
    deduped = correlate_alerts(events)
    assert len(deduped) == 1
    assert deduped[0]["observation_count"] == 3

def test_22_alert_generation_threshold():
    high_threat = {"threat_id": "THR-TEST-H", "threat_name": "High Alert Lure", "threat_category": "PHISHING", "severity": "HIGH", "risk_score": 75, "confidence_score": 80}
    low_threat = {"threat_id": "THR-TEST-L", "threat_name": "Low Noise", "threat_category": "WEB THREATS", "severity": "INFORMATIONAL", "risk_score": 15, "confidence_score": 40}
    assert generate_threat_alert(high_threat) is not None
    assert generate_threat_alert(low_threat) is None

def test_23_attack_coverage_analysis():
    records = [
        {"mitre_tactic_optional": "Initial Access", "mitre_technique_optional": "Spearphishing Link", "mitre_technique_id": "T1566.002"},
        {"mitre_tactic_optional": "Initial Access", "mitre_technique_optional": "Spearphishing Link", "mitre_technique_id": "T1566.002"},
        {"mitre_tactic_optional": "Impact", "mitre_technique_optional": "Data Encrypted", "mitre_technique_id": "T1486"}
    ]
    res = analyze_attack_coverage(records)
    assert res["top_tactics"][0]["tactic"] == "Initial Access"
    assert res["top_tactics"][0]["count"] == 2

def test_24_cve_priority_scoring():
    p = calculate_vulnerability_priority(7.5, "HIGH", True, "POC_PUBLIC_DEFENSIVE_ONLY", "YES")
    assert 0 <= p["priority_score"] <= 100

# ----------------- 5. DATABASE & THREAT SERVICE (25 - 29) -----------------
def test_25_db_connection_and_seeded_records():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM THREATS")
    count = cur.fetchone()[0]
    conn.close()
    assert count >= 2000

def test_26_get_threat_by_id():
    t = get_threat_by_id("THR-2026-001")
    assert t is not None
    assert t["threat_id"] == "THR-2026-001"
    assert t["indicator_value"] == "login-check.invalid"
    assert len(t["timeline"]) > 0

def test_27_filter_threats_by_severity():
    res = get_threats(severity="CRITICAL", limit=10)
    for t in res["threats"]:
        assert t["severity"] == "CRITICAL"

def test_28_filter_threats_by_category():
    res = get_threats(category="RANSOMWARE", limit=10)
    for t in res["threats"]:
        assert t["category"] == "RANSOMWARE"

def test_29_sort_threats_highest_risk():
    res = get_threats(sort_by="highest_risk", limit=5)
    risks = [t["risk_score"] for t in res["threats"]]
    assert risks == sorted(risks, reverse=True)

# ----------------- 6. REST API INTEGRATION TESTS (30 - 37) -----------------
@pytest.fixture
def api_client():
    from backend.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_30_api_get_threats(api_client):
    res = api_client.get("/api/threats?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert "threats" in data
    assert len(data["threats"]) == 5

def test_31_api_get_threat_details(api_client):
    res = api_client.get("/api/threats/THR-2026-001")
    assert res.status_code == 200
    data = res.get_json()
    assert data["threat_id"] == "THR-2026-001"

def test_32_api_dashboard_stats(api_client):
    res = api_client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert data["cards"]["total_threats"] >= 2000

def test_33_api_search_endpoint(api_client):
    res = api_client.get("/api/indicators/search?query=login-check.invalid")
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_known_in_dataset"] is True

def test_34_api_awareness_modules(api_client):
    res = api_client.get("/api/awareness/modules")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["modules"]) >= 15

def test_35_api_quiz_endpoint(api_client):
    res = api_client.get("/api/quiz")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_questions"] >= 30

def test_36_api_quiz_submission_and_scoring(api_client):
    submission = {
        "answers": {
            "1": 2, # Correct
            "2": 1, # Correct
            "3": 1  # Correct
        }
    }
    res = api_client.post("/api/quiz/submit", json=submission)
    assert res.status_code == 200
    data = res.get_json()
    assert "overall_score" in data
    assert "classification" in data
    assert data["correct_answers"] >= 3

def test_37_api_update_threat_status(api_client):
    res = api_client.put("/api/threats/THR-2026-001", json={"status": "CLOSED"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "CLOSED"
    # Revert back to MONITORING
    api_client.put("/api/threats/THR-2026-001", json={"status": "MONITORING"})
