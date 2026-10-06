"""
REST API Blueprint Routes
Defines clean, documented, defensive REST endpoints for:
- /api/threats (GET, POST)
- /api/threats/<id> (GET, PUT)
- /api/threats/<id>/notes (POST)
- /api/indicators/search (GET)
- /api/dashboard/stats (GET)
- /api/dashboard/trends (GET)
- /api/alerts (GET)
- /api/alerts/<id>/status (PUT)
- /api/vulnerabilities (GET)
- /api/awareness/modules (GET)
- /api/quiz (GET)
- /api/quiz/submit (POST)
- /api/correlation/clusters (GET)
"""

from flask import Blueprint, request, jsonify
import json
import os
from datetime import datetime
from backend.models.database import get_db_connection
from backend.services.threat_service import (
    get_threats, get_threat_by_id, search_indicator_service,
    get_dashboard_statistics, add_analyst_note_service
)
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk, calculate_vulnerability_priority
from backend.services.correlation_engine import correlate_threats, correlate_alerts

api_bp = Blueprint("api", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@api_bp.route("/threats", methods=["GET"])
def api_get_threats():
    severity = request.args.get("severity")
    category = request.args.get("category")
    status = request.args.get("status")
    ind_type = request.args.get("indicator_type")
    sort_by = request.args.get("sort_by", "newest")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    data = get_threats(
        severity=severity,
        category=category,
        indicator_type=ind_type,
        status=status,
        sort_by=sort_by,
        limit=limit,
        offset=offset
    )
    return jsonify(data), 200

@api_bp.route("/threats/<threat_id>", methods=["GET"])
def api_get_threat_detail(threat_id):
    threat = get_threat_by_id(threat_id)
    if not threat:
        return jsonify({"error": "Threat record not found in local repository"}), 404
    return jsonify(threat), 200

@api_bp.route("/threats", methods=["POST"])
def api_create_threat():
    body = request.get_json() or {}
    name = body.get("threat_name")
    category = body.get("category", "PHISHING")
    indicator_val = body.get("indicator_value")

    if not name or not indicator_val:
        return jsonify({"error": "Missing required fields: threat_name and indicator_value"}), 400

    val_res = validate_indicator(indicator_val)
    if not val_res["valid"]:
        return jsonify({"error": f"Invalid indicator syntax: {val_res['validation_notes']}"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM THREATS")
    next_id = f"THR-2026-{(cur.fetchone()[0] + 1):04d}"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev = body.get("severity", "MEDIUM")
    risk_info = calculate_threat_risk(sev, 70, now_str)

    cur.execute("""
    INSERT INTO THREATS (threat_id, threat_name, category, description, severity, risk_score, confidence_score, status, first_seen, last_seen, country_or_region)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        next_id, name, category, body.get("description", "Analyst submitted record"),
        sev, risk_info["risk_score"], 70.0, "UNDER_REVIEW", now_str, now_str, "Global"
    ))

    cur.execute("""
    INSERT INTO INDICATORS (threat_id, indicator_type, indicator_value, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?)
    """, (next_id, val_res["indicator_type"], val_res["normalized_value"], now_str, now_str))

    cur.execute("""
    INSERT INTO SOURCES (threat_id, source_name, reliability)
    VALUES (?, ?, ?)
    """, (next_id, "Internal Analyst Submission", "A – Highly Reliable"))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "threat_id": next_id, "risk_score": risk_info["risk_score"]}), 201

@api_bp.route("/threats/<threat_id>", methods=["PUT"])
def api_update_threat(threat_id):
    body = request.get_json() or {}
    new_status = body.get("status")
    if not new_status:
        return jsonify({"error": "Missing 'status' in request body"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE THREATS SET status = ? WHERE threat_id = ?", (new_status.upper(), threat_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()

    if not updated:
        return jsonify({"error": "Threat not found"}), 404
    return jsonify({"success": True, "threat_id": threat_id, "status": new_status.upper()}), 200

@api_bp.route("/threats/<threat_id>/notes", methods=["POST"])
def api_add_threat_note(threat_id):
    body = request.get_json() or {}
    note_text = body.get("note")
    author = body.get("author", "SOC Analyst (Tier-1)")
    if not note_text:
        return jsonify({"error": "Note text is required"}), 400

    res = add_analyst_note_service(threat_id, note_text, author)
    return jsonify(res), 201

@api_bp.route("/indicators/search", methods=["GET"])
def api_search_indicator():
    q = request.args.get("query", "").strip()
    if not q:
        return jsonify({"error": "Query parameter 'query' is required"}), 400
    res = search_indicator_service(q)
    return jsonify(res), 200

@api_bp.route("/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    data = get_dashboard_statistics()
    return jsonify(data), 200

@api_bp.route("/dashboard/trends", methods=["GET"])
def api_dashboard_trends():
    conn = get_db_connection()
    cur = conn.cursor()
    # Group observations by week
    cur.execute("""
    SELECT substr(last_seen, 1, 10) as day, COUNT(*) as threat_count, AVG(risk_score) as avg_risk
    FROM THREATS
    GROUP BY day
    ORDER BY day DESC
    LIMIT 14
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"trends": list(reversed(rows))}), 200

@api_bp.route("/alerts", methods=["GET"])
def api_get_alerts():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT a.*, t.threat_name, t.category, i.indicator_value
    FROM ALERTS a
    JOIN THREATS t ON a.threat_id = t.threat_id
    JOIN INDICATORS i ON t.threat_id = i.threat_id
    ORDER BY a.created_at DESC
    LIMIT 100
    """)
    alerts = [dict(r) for r in cur.fetchall()]
    conn.close()
    
    # Run alert correlation to mitigate fatigue
    correlated = correlate_alerts(alerts)
    return jsonify({"total": len(alerts), "alerts": alerts[:40], "correlated_clusters": correlated[:15]}), 200

@api_bp.route("/alerts/<alert_id>/status", methods=["PUT"])
def api_update_alert_status(alert_id):
    body = request.get_json() or {}
    new_status = body.get("status")
    if not new_status:
        return jsonify({"error": "Missing status parameter"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE ALERTS SET status = ? WHERE alert_id = ?", (new_status.upper(), alert_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    if not updated:
        return jsonify({"error": "Alert ID not found"}), 404
    return jsonify({"success": True, "alert_id": alert_id, "status": new_status.upper()}), 200

@api_bp.route("/vulnerabilities", methods=["GET"])
def api_get_vulnerabilities():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM VULNERABILITIES ORDER BY priority_score DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"vulnerabilities": rows}), 200

@api_bp.route("/awareness/modules", methods=["GET"])
def api_get_awareness_modules():
    modules_path = os.path.join(BASE_DIR, "awareness", "modules.json")
    if not os.path.exists(modules_path):
        return jsonify({"error": "Modules definition not found"}), 404
    with open(modules_path, "r", encoding="utf-8") as f:
        modules = json.load(f)
    return jsonify({"modules": modules}), 200

@api_bp.route("/quiz", methods=["GET"])
def api_get_quiz():
    quiz_path = os.path.join(BASE_DIR, "awareness", "quiz_questions.json")
    if not os.path.exists(quiz_path):
        return jsonify({"error": "Quiz questions not found"}), 404
    with open(quiz_path, "r", encoding="utf-8") as f:
        questions = json.load(f)
    
    # Return questions sanitized of answers for client-side rendering
    sanitized = []
    for q in questions:
        sanitized.append({
            "id": q["id"],
            "category": q["category"],
            "question": q["question"],
            "options": q["options"]
        })
    return jsonify({"total_questions": len(sanitized), "questions": sanitized}), 200

@api_bp.route("/quiz/submit", methods=["POST"])
def api_submit_quiz():
    body = request.get_json() or {}
    user_answers = body.get("answers", {})  # { question_id: selected_index }

    quiz_path = os.path.join(BASE_DIR, "awareness", "quiz_questions.json")
    with open(quiz_path, "r", encoding="utf-8") as f:
        original = json.load(f)

    correct_cnt = 0
    cat_stats = {}
    detailed_results = []

    for item in original:
        qid = str(item["id"])
        cat = item["category"]
        if cat not in cat_stats:
            cat_stats[cat] = {"total": 0, "correct": 0}
        cat_stats[cat]["total"] += 1

        selected = user_answers.get(qid)
        is_correct = (selected == item["correct_answer"]) if selected is not None else False
        if is_correct:
            correct_cnt += 1
            cat_stats[cat]["correct"] += 1

        detailed_results.append({
            "id": item["id"],
            "category": cat,
            "question": item["question"],
            "selected_index": selected,
            "correct_index": item["correct_answer"],
            "is_correct": is_correct,
            "explanation": item["explanation"]
        })

    overall_score = round((correct_cnt / len(original)) * 100, 1)

    # Classification
    if overall_score <= 40:
        band = "Needs Improvement"
    elif overall_score <= 60:
        band = "Basic Awareness"
    elif overall_score <= 80:
        band = "Good Awareness"
    else:
        band = "Strong Awareness"

    # Category analysis & recommendations
    cat_breakdown = {}
    recommendations = []
    for cat, stats in cat_stats.items():
        pct = round((stats["correct"] / stats["total"]) * 100, 1)
        cat_breakdown[cat] = {
            "score": pct,
            "correct": stats["correct"],
            "total": stats["total"]
        }
        if pct < 70:
            recommendations.append({
                "category": cat,
                "score": pct,
                "recommendation": f"Priority Review: Complete the {cat} awareness training module to strengthen defensive habits."
            })

    # Save to database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO QUIZ_RESULTS (overall_score, category_breakdown_json, recommendations_json, created_at)
    VALUES (?, ?, ?, ?)
    """, (overall_score, json.dumps(cat_breakdown), json.dumps(recommendations), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    return jsonify({
        "overall_score": overall_score,
        "classification": band,
        "total_questions": len(original),
        "correct_answers": correct_cnt,
        "category_breakdown": cat_breakdown,
        "recommendations": recommendations,
        "detailed_results": detailed_results
    }), 200

@api_bp.route("/correlation/clusters", methods=["GET"])
def api_get_correlation_clusters():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT t.threat_id, t.threat_name, t.category as threat_category, t.severity, t.risk_score,
           t.campaign_id, i.indicator_value
    FROM THREATS t
    JOIN INDICATORS i ON t.threat_id = i.threat_id
    WHERE t.campaign_id IS NOT NULL AND t.campaign_id != ''
    LIMIT 300
    """)
    records = [dict(r) for r in cur.fetchall()]
    conn.close()

    clusters = correlate_threats(records)
    return jsonify({"clusters": clusters}), 200
