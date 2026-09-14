"""
ThreatFox (abuse.ch) connector.
Docs: https://threatfox.abuse.ch/api/
No API key required for read queries, but an Auth-Key raises your rate limit.
"""
import os
import requests

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEED_NAME = "threatfox"

# ThreatFox ioc_type values -> our normalized types
TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",
}


def fetch(days: int = 1):
    """Return a list of normalized IOC dicts from the last `days` days."""
    headers = {}
    key = os.getenv("THREATFOX_API_KEY")
    if key:
        headers["Auth-Key"] = key

    resp = requests.post(
        API_URL,
        json={"query": "get_iocs", "days": days},
        headers=headers,
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned status: {data.get('query_status')}")

    results = []
    for item in data.get("data", []):
        raw_type = item.get("ioc_type")
        normalized_type = TYPE_MAP.get(raw_type)
        if not normalized_type:
            continue  # skip types we don't model (e.g. asn)

        value = item.get("ioc")
        if normalized_type == "ip" and ":" in value:
            value = value.split(":")[0]  # strip port from ip:port pairs

        results.append(
            {
                "ioc_type": normalized_type,
                "value": value,
                "threat_type": item.get("threat_type"),
                "malware_family": item.get("malware_printable") or item.get("malware"),
                "confidence": item.get("confidence_level", 50),
                "reference": item.get("reference") or f"https://threatfox.abuse.ch/browse/",
                "source": FEED_NAME,
            }
        )
    return results
