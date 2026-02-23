"""
AbuseIPDB API client.
Provides IP reputation lookups with standardized output.
"""
import requests
from config import ABUSEIPDB_API_KEY

BASE_URL = "https://api.abuseipdb.com/api/v2"


def _headers():
    return {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }


def _api_available():
    return bool(ABUSEIPDB_API_KEY)


def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for the reputation of an IP address.
    Returns a standardized dictionary.
    """
    if not _api_available():
        return {"error": "AbuseIPDB API key not configured"}
    try:
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }
        resp = requests.get(
            f"{BASE_URL}/check",
            headers=_headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "source": "abuseipdb",
            "indicator": ip,
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "is_whitelisted": data.get("isWhitelisted", False),
            "raw": data,
        }
    except requests.RequestException as exc:
        return {"error": str(exc), "source": "abuseipdb", "indicator": ip}
