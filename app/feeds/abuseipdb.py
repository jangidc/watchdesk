"""
AbuseIPDB connector.
Docs: https://docs.abuseipdb.com/
Requires a free API key -> https://www.abuseipdb.com/account/api
Without a key, fetch() returns an empty list instead of erroring, so the rest
of the platform keeps working with the other two feeds.
"""
import os
import requests

API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
FEED_NAME = "abuseipdb"


def fetch(confidence_minimum: int = 75, limit: int = 500):
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return []  # gracefully skip; caller logs this as "skipped", not "error"

    headers = {"Key": key, "Accept": "application/json"}
    params = {"confidenceMinimum": confidence_minimum, "limit": limit}

    resp = requests.get(API_URL, headers=headers, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for item in data.get("data", []):
        results.append(
            {
                "ioc_type": "ip",
                "value": item.get("ipAddress"),
                "threat_type": "reported_abuse",
                "malware_family": None,
                "confidence": item.get("abuseConfidenceScore", confidence_minimum),
                "reference": f"https://www.abuseipdb.com/check/{item.get('ipAddress')}",
                "source": FEED_NAME,
            }
        )
    return results
