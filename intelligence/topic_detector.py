"""
Emerging threat topic detector.
Attempts BERTopic first; falls back to TF-IDF + KMeans when
BERTopic / hdbscan cannot be installed (common on Windows without C build tools).
"""
from datetime import datetime, timedelta, timezone
from storage.mongo_client import get_db
from config import COLLECTION_THREAT_INTEL, COLLECTION_TOPICS

# ── Try to import BERTopic ────────────────────────────────────────
try:
    from bertopic import BERTopic
    BERTOPIC_AVAILABLE = True
except ImportError:
    BERTOPIC_AVAILABLE = False

_topic_model = None


# ================================================================
# Public API
# ================================================================

def detect_topics(texts: list[str]) -> list[dict]:
    """
    Run topic detection on a list of texts.
    Returns a list of dicts:
        {topic_id, keywords, count, representative_doc}
    """
    if len(texts) < 5:
        return []

    if BERTOPIC_AVAILABLE:
        return _detect_bertopic(texts)
    return _detect_fallback(texts)


def get_emerging_topics(days: int = 7) -> list[dict]:
    """
    Fetch recent threat texts from MongoDB (last *days* days),
    run topic detection, store results, and return them.
    """
    db = get_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    docs = list(
        db[COLLECTION_THREAT_INTEL].find(
            {"timestamp": {"$gte": cutoff}, "classification.is_threat": True},
            {"_id": 0, "input_value": 1},
        )
    )
    texts = [d.get("input_value", "") for d in docs if d.get("input_value")]

    if len(texts) < 5:
        return _get_stored_topics()

    topics = detect_topics(texts)

    if topics:
        db[COLLECTION_TOPICS].delete_many({})
        db[COLLECTION_TOPICS].insert_many(
            [{**t, "detected_at": datetime.now(timezone.utc)} for t in topics]
        )

    return topics


# ================================================================
# BERTopic path
# ================================================================

def _detect_bertopic(texts):
    global _topic_model
    if _topic_model is None:
        print("[TopicDetector] Loading BERTopic model …")
        _topic_model = BERTopic(language="english", min_topic_size=3, verbose=False)
        print("[TopicDetector] Model ready.")

    topics_list, _probs = _topic_model.fit_transform(texts)
    topic_info = _topic_model.get_topic_info()

    results = []
    for _, row in topic_info.iterrows():
        tid = row["Topic"]
        if tid == -1:
            continue
        keywords_raw = _topic_model.get_topic(tid)
        keywords = [w for w, _ in keywords_raw[:8]]
        rep_idx = next((i for i, t in enumerate(topics_list) if t == tid), None)
        rep_doc = texts[rep_idx] if rep_idx is not None else ""
        results.append({
            "topic_id": int(tid),
            "keywords": keywords,
            "count": int(row["Count"]),
            "representative_doc": rep_doc[:300],
        })
    return results


# ================================================================
# Fallback: TF-IDF + KMeans
# ================================================================

def _detect_fallback(texts):
    """Lightweight topic detection without BERTopic."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    import numpy as np

    n_clusters = min(max(2, len(texts) // 5), 8)

    vectorizer = TfidfVectorizer(
        max_features=1000,
        stop_words="english",
        max_df=0.9,
        min_df=2 if len(texts) > 10 else 1,
    )
    try:
        tfidf_matrix = vectorizer.fit_transform(texts)
    except ValueError:
        return []

    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(tfidf_matrix)

    feature_names = vectorizer.get_feature_names_out()
    results = []

    for cid in range(n_clusters):
        member_indices = [i for i, l in enumerate(labels) if l == cid]
        if not member_indices:
            continue

        # top keywords by centroid weight
        order = km.cluster_centers_[cid].argsort()[::-1]
        keywords = [feature_names[idx] for idx in order[:8]]

        results.append({
            "topic_id": int(cid),
            "keywords": keywords,
            "count": len(member_indices),
            "representative_doc": texts[member_indices[0]][:300],
        })

    results.sort(key=lambda t: t["count"], reverse=True)
    return results


# ================================================================
# Helpers
# ================================================================

def _get_stored_topics() -> list[dict]:
    """Return previously stored topics if fresh detection isn't possible."""
    db = get_db()
    return list(
        db[COLLECTION_TOPICS].find({}, {"_id": 0}).sort("count", -1).limit(20)
    )
