"""
The core CTI pipeline: collect -> normalize -> correlate -> store.

Each feed module returns a list of dicts already normalized to a common shape
(ioc_type, value, threat_type, malware_family, confidence, reference, source).
This module's job is correlation: if the same indicator shows up across
multiple independent feeds, that's a stronger signal than any single feed
alone, so we raise its confidence and severity rather than storing duplicates.
"""
from app import db, log
from app.models import IOC, FeedRun, utcnow
from app.feeds import threatfox, urlhaus, abuseipdb

FEEDS = [
    ("threatfox", lambda: threatfox.fetch(days=1)),
    ("urlhaus", lambda: urlhaus.fetch()),
    ("abuseipdb", lambda: abuseipdb.fetch()),
]


def _severity_from_confidence(confidence: int, source_count: int) -> str:
    if source_count >= 3 or confidence >= 90:
        return "critical"
    if source_count == 2 or confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def _upsert(item: dict) -> str:
    """Insert a new IOC or merge this sighting into an existing one.
    Returns 'new' or 'updated'.
    """
    existing = IOC.query.filter_by(
        ioc_type=item["ioc_type"], value=item["value"]
    ).first()

    if existing is None:
        record = IOC(
            ioc_type=item["ioc_type"],
            value=item["value"],
            threat_type=item.get("threat_type"),
            malware_family=item.get("malware_family"),
            confidence=item.get("confidence", 50),
            sources=item["source"],
            source_count=1,
            reference=item.get("reference"),
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        record.severity = _severity_from_confidence(record.confidence, 1)
        db.session.add(record)
        return "new"

    # Already known — correlate rather than duplicate.
    known_sources = set(existing.sources.split(",")) if existing.sources else set()
    if item["source"] not in known_sources:
        known_sources.add(item["source"])
        existing.sources = ",".join(sorted(known_sources))
        existing.source_count = len(known_sources)

    existing.confidence = max(existing.confidence, item.get("confidence", 50))
    existing.malware_family = existing.malware_family or item.get("malware_family")
    existing.threat_type = existing.threat_type or item.get("threat_type")
    existing.severity = _severity_from_confidence(existing.confidence, existing.source_count)
    existing.last_seen = utcnow()
    return "updated"


def run_all_feeds():
    """Pull every configured feed once, correlate results, and record feed health."""
    for name, fetch_fn in FEEDS:
        new_count = 0
        updated_count = 0
        try:
            items = fetch_fn()
            if not items and name == "abuseipdb":
                db.session.add(
                    FeedRun(feed_name=name, status="skipped", message="No API key configured")
                )
                db.session.commit()
                log.info("Feed %s skipped (no API key)", name)
                continue

            for item in items:
                outcome = _upsert(item)
                if outcome == "new":
                    new_count += 1
                else:
                    updated_count += 1

            db.session.commit()
            db.session.add(
                FeedRun(
                    feed_name=name,
                    status="success",
                    new_iocs=new_count,
                    updated_iocs=updated_count,
                    message=f"Pulled {len(items)} indicators",
                )
            )
            db.session.commit()
            log.info(
                "Feed %s: %s new, %s updated (of %s pulled)",
                name, new_count, updated_count, len(items),
            )
        except Exception as exc:  # noqa: BLE001 - a bad feed should never crash the app
            db.session.rollback()
            db.session.add(FeedRun(feed_name=name, status="error", message=str(exc)[:500]))
            db.session.commit()
            log.error("Feed %s failed: %s", name, exc)
