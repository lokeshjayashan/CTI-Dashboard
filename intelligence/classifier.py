"""
BERT-based threat classifier using zero-shot classification.
Uses facebook/bart-large-mnli so it works without fine-tuning.
"""
from transformers import pipeline
from config import CLASSIFIER_MODEL, THREAT_CATEGORIES
from processing.preprocessor import prepare_for_model

_classifier = None


def _get_classifier():
    """Lazy-load the zero-shot classification pipeline."""
    global _classifier
    if _classifier is None:
        print("[Classifier] Loading model — this may take a moment on first run …")
        _classifier = pipeline(
            "zero-shot-classification",
            model=CLASSIFIER_MODEL,
            device=-1,  # CPU; set to 0 for GPU
        )
        print("[Classifier] Model loaded successfully.")
    return _classifier


def classify_threat(text: str) -> dict:
    """
    Classify free text into one of the THREAT_CATEGORIES.

    Returns
    -------
    dict
        {
            "is_threat": bool,
            "category": str,          # best-matching category
            "confidence": float,      # 0-1
            "all_scores": dict,       # category → score
            "input_text": str,
        }
    """
    cleaned = prepare_for_model(text)
    if not cleaned:
        return {
            "is_threat": False,
            "category": "unknown",
            "confidence": 0.0,
            "all_scores": {},
            "input_text": text,
        }

    try:
        clf = _get_classifier()

        # First: is this text security-related at all?
        security_check = clf(
            cleaned,
            candidate_labels=["cybersecurity threat", "benign / not a threat"],
        )
        threat_score = 0.0
        for label, score in zip(security_check["labels"], security_check["scores"]):
            if "threat" in label.lower():
                threat_score = score
                break

        is_threat = threat_score >= 0.50

        # Second: classify among threat categories
        result = clf(cleaned, candidate_labels=THREAT_CATEGORIES)
        all_scores = {
            label: round(score, 4)
            for label, score in zip(result["labels"], result["scores"])
        }
        best_label = result["labels"][0]
        best_score = round(result["scores"][0], 4)

        return {
            "is_threat": is_threat,
            "category": best_label if is_threat else "benign",
            "confidence": best_score if is_threat else round(1 - threat_score, 4),
            "all_scores": all_scores,
            "input_text": text,
        }

    except Exception as exc:
        print(f"[Classifier] Error: {exc}")
        return {
            "is_threat": False,
            "category": "error",
            "confidence": 0.0,
            "all_scores": {},
            "input_text": text,
            "error": str(exc),
        }
