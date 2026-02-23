"""
CTI Dashboard — Flask application entry point.
Serves the dashboard and exposes REST API endpoints.
"""
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify

from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    COLLECTION_THREAT_INTEL,
)
from processing.preprocessor import (
    detect_input_type, validate_ip, validate_url, prepare_for_model,
)
from intelligence.classifier import classify_threat
from intelligence.topic_detector import get_emerging_topics
from ingestion.virustotal_client import get_url_report, get_domain_report
from ingestion.abuseipdb_client import check_ip
from storage.mongo_client import get_db, is_connected
from storage.cache import get_cached, set_cache

app = Flask(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Presentation endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "mongo_connected": is_connected(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Full analysis pipeline.
    Accepts JSON: {"type": "ip"|"url"|"text", "value": "..."}
    If type is omitted it is auto-detected.
    """
    body = request.get_json(force=True)
    value = body.get("value", "").strip()
    if not value:
        return jsonify({"error": "value is required"}), 400

    input_type = body.get("type") or detect_input_type(value)
    result = {"input_type": input_type, "input_value": value}

    # ── 1. API reputation lookup (with cache) ─────────────────
    reputation = {}
    if input_type == "ip":
        cached = get_cached(value, "abuseipdb")
        if cached:
            reputation = cached.get("data", cached)
            reputation["cached"] = True
        else:
            reputation = check_ip(value)
            if "error" not in reputation:
                set_cache(value, "abuseipdb", reputation)
                reputation["cached"] = False

    elif input_type == "url":
        cached = get_cached(value, "virustotal")
        if cached:
            reputation = cached.get("data", cached)
            reputation["cached"] = True
        else:
            reputation = get_url_report(value)
            if "error" not in reputation:
                set_cache(value, "virustotal", reputation)
                reputation["cached"] = False

    result["reputation"] = reputation

    # ── 2. AI classification ──────────────────────────────────
    text_to_classify = value
    if input_type == "ip" and reputation:
        if "error" not in reputation and reputation.get("abuse_score") is not None:
            # build a richer sentence for the classifier
            abuse = reputation.get("abuse_score", 0)
            reports = reputation.get("total_reports", 0)
            text_to_classify = (
                f"IP address {value} has abuse confidence score {abuse}% "
                f"and {reports} abuse reports."
            )
        else:
            text_to_classify = f"Analyze this IP address for threats: {value}"
    elif input_type == "url" and reputation:
        positives = reputation.get("positives", 0)
        total = reputation.get("total", 0)
        if "error" not in reputation and total > 0:
            text_to_classify = (
                f"URL {value} flagged by {positives} out of {total} security vendors."
            )
        else:
            # No API data available — give the classifier the raw URL
            text_to_classify = f"Analyze this URL for threats: {value}"

    classification = classify_threat(text_to_classify)
    result["classification"] = classification

    # ── 3. Severity derivation ─────────────────────────────────
    result["severity"] = _derive_severity(input_type, reputation, classification)

    # ── 4. Persist to MongoDB ─────────────────────────────────
    try:
        record = {**result, "timestamp": datetime.now(timezone.utc)}
        # remove non-serialisable raw payload for cleanliness
        if "raw" in record.get("reputation", {}):
            record["reputation"] = {
                k: v for k, v in record["reputation"].items() if k != "raw"
            }
        get_db()[COLLECTION_THREAT_INTEL].insert_one(record)
    except Exception as exc:
        result["storage_warning"] = str(exc)

    # Remove MongoDB _id before returning
    result.pop("_id", None)
    return jsonify(result)


@app.route("/api/threats")
def threats():
    """Return the most recent threat intel records."""
    limit = request.args.get("limit", 50, type=int)
    db = get_db()
    docs = list(
        db[COLLECTION_THREAT_INTEL]
        .find({}, {"_id": 0, "reputation.raw": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    # Convert datetime objects to ISO strings
    for d in docs:
        if "timestamp" in d and hasattr(d["timestamp"], "isoformat"):
            d["timestamp"] = d["timestamp"].isoformat()
    return jsonify(docs)


@app.route("/api/stats")
def stats():
    """Aggregate statistics for the dashboard charts."""
    db = get_db()
    col = db[COLLECTION_THREAT_INTEL]

    # Category distribution
    cat_pipeline = [
        {"$group": {"_id": "$classification.category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    categories = {
        doc["_id"]: doc["count"]
        for doc in col.aggregate(cat_pipeline)
        if doc["_id"]
    }

    # Top malicious IPs
    ip_pipeline = [
        {"$match": {"input_type": "ip", "classification.is_threat": True}},
        {"$group": {"_id": "$input_value", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_ips = [
        {"ip": doc["_id"], "count": doc["count"]}
        for doc in col.aggregate(ip_pipeline)
    ]

    # Severity distribution
    sev_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    severities = {
        doc["_id"]: doc["count"]
        for doc in col.aggregate(sev_pipeline)
        if doc["_id"]
    }

    # Total counts
    total = col.count_documents({})
    threats_count = col.count_documents({"classification.is_threat": True})

    return jsonify({
        "categories": categories,
        "top_ips": top_ips,
        "severities": severities,
        "total": total,
        "threats": threats_count,
    })


@app.route("/api/topics")
def topics():
    """Return emerging threat topics."""
    try:
        result = get_emerging_topics()
        # Convert any datetime objects
        for t in result:
            if "detected_at" in t and hasattr(t["detected_at"], "isoformat"):
                t["detected_at"] = t["detected_at"].isoformat()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc), "topics": []})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _derive_severity(input_type, reputation, classification):
    """Map reputation + classification into a severity label."""
    if not classification.get("is_threat"):
        return "low"

    confidence = classification.get("confidence", 0)

    if input_type == "ip":
        abuse = reputation.get("abuse_score", 0)
        if abuse >= 80 or confidence >= 0.85:
            return "critical"
        if abuse >= 50 or confidence >= 0.65:
            return "high"
        if abuse >= 25:
            return "medium"
        return "low"

    if input_type == "url":
        positives = reputation.get("positives", 0)
        if positives >= 10 or confidence >= 0.85:
            return "critical"
        if positives >= 5 or confidence >= 0.65:
            return "high"
        if positives >= 2:
            return "medium"
        return "low"

    # text-only
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.40:
        return "medium"
    return "low"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    print("🛡️  CTI Dashboard starting …")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
