import requests, json

r = requests.post("http://localhost:5000/api/analyze", json={"type": "url", "value": "https://www.google.com/"})
d = r.json()

rep = d.get("reputation", {})
cls = d.get("classification", {})

print(f"positives = {rep.get('positives')}")
print(f"total = {rep.get('total')}")
print(f"cached = {rep.get('cached')}")
print(f"error = {rep.get('error')}")
print()
print(f"is_threat = {cls.get('is_threat')}")
print(f"category = {cls.get('category')}")
print(f"confidence = {cls.get('confidence')}")
print(f"override_reason = {cls.get('override_reason', 'NONE')}")
print(f"input_text = {cls.get('input_text', 'N/A')[:200]}")
