"""
URLhaus (abuse.ch) connector.
Docs: https://urlhaus-api.abuse.ch/
No API key required.
"""
import requests

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
FEED_NAME = "urlhaus"


def fetch():
    """Return a list of normalized IOC dicts for recently reported malicious URLs."""
    resp = requests.post(API_URL, timeout=20)
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus returned status: {data.get('query_status')}")

    results = []
    for item in data.get("urls", []):
        tags = item.get("tags") or []
        results.append(
            {
                "ioc_type": "url",
                "value": item.get("url"),
                "threat_type": item.get("threat", "malware_download"),
                "malware_family": ", ".join(tags) if tags else None,
                "confidence": 75 if item.get("url_status") == "online" else 50,
                "reference": item.get("urlhaus_reference"),
                "source": FEED_NAME,
            }
        )
    return results
