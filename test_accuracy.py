"""Quick test for classification accuracy."""
import requests

BASE = "http://localhost:5000/api/analyze"

test_cases = [
    {"type": "url", "value": "https://www.google.com/", "expected_safe": True},
    {"type": "url", "value": "https://www.youtube.com/", "expected_safe": True},
    {"type": "url", "value": "https://www.wikipedia.org/", "expected_safe": True},
    {"type": "ip",  "value": "8.8.8.8", "expected_safe": True},
    {"type": "text", "value": "Ransomware attack spreading via phishing emails", "expected_safe": False},
    {"type": "text", "value": "spyware", "expected_safe": False},
]

for tc in test_cases:
    r = requests.post(BASE, json={"type": tc["type"], "value": tc["value"]})
    d = r.json()
    cls = d["classification"]
    is_threat = cls["is_threat"]
    cat = cls["category"]
    conf = cls["confidence"]
    override = cls.get("override_reason", "")
    
    correct = (not is_threat) == tc["expected_safe"]
    mark = "PASS" if correct else "FAIL"
    
    print(f"[{mark}] {tc['value']}")
    print(f"       threat={is_threat}  category={cat}  confidence={conf}")
    if override:
        print(f"       override: {override}")
    print()
