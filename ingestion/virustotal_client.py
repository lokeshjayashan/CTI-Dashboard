"""
VirusTotal API client.
Provides URL/domain reputation lookups with standardized output.
"""
import requests
from config import VIRUSTOTAL_API_KEY

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers():
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def _api_available():
    """Check whether an API key has been configured."""
    return bool(VIRUSTOTAL_API_KEY)


def scan_url(url: str) -> dict:
    """Submit a URL for scanning and return the analysis id."""
    if not _api_available():
        return {"error": "VirusTotal API key not configured"}
    try:
        resp = requests.post(
            f"{BASE_URL}/urls",
            headers=_headers(),
            data={"url": url},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "source": "virustotal",
            "indicator": url,
            "analysis_id": data.get("data", {}).get("id", ""),
            "raw": data,
        }
    except requests.RequestException as exc:
        return {"error": str(exc), "source": "virustotal", "indicator": url}


def get_url_report(url: str) -> dict:
    """Fetch the reputation report for a URL."""
    if not _api_available():
        return {"error": "VirusTotal API key not configured"}
    try:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"{BASE_URL}/urls/{url_id}",
            headers=_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "indicator": url,
            "positives": stats.get("malicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "details": stats,
            "raw": data,
        }
    except requests.RequestException as exc:
        return {"error": str(exc), "source": "virustotal", "indicator": url}


def get_domain_report(domain: str) -> dict:
    """Fetch the reputation report for a domain."""
    if not _api_available():
        return {"error": "VirusTotal API key not configured"}
    try:
        resp = requests.get(
            f"{BASE_URL}/domains/{domain}",
            headers=_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "indicator": domain,
            "positives": stats.get("malicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "details": stats,
            "raw": data,
        }
    except requests.RequestException as exc:
        return {"error": str(exc), "source": "virustotal", "indicator": domain}
