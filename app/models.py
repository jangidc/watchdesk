from datetime import datetime, timezone
from app import db


def utcnow():
    return datetime.now(timezone.utc)


class IOC(db.Model):
    """A single indicator of compromise, normalized across feeds."""

    __tablename__ = "iocs"

    id = db.Column(db.Integer, primary_key=True)

    # Core indicator
    ioc_type = db.Column(db.String(20), nullable=False, index=True)  # ip, domain, url, hash
    value = db.Column(db.String(512), nullable=False, index=True)

    # Context
    threat_type = db.Column(db.String(120))  # e.g. botnet_cc, phishing, malware_download
    malware_family = db.Column(db.String(120))
    confidence = db.Column(db.Integer, default=50)  # 0-100
    severity = db.Column(db.String(20), default="medium")  # low, medium, high, critical

    # Provenance
    sources = db.Column(db.String(255), default="")  # comma-separated list of feed names
    source_count = db.Column(db.Integer, default=1)  # how many independent feeds reported this
    reference = db.Column(db.String(512))  # link back to the feed's own report page

    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)

    __table_args__ = (
        db.UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.ioc_type,
            "value": self.value,
            "threat_type": self.threat_type,
            "malware_family": self.malware_family,
            "confidence": self.confidence,
            "severity": self.severity,
            "sources": self.sources,
            "source_count": self.source_count,
            "reference": self.reference,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class FeedRun(db.Model):
    """Tracks the health/history of each feed pull, for the status panel."""

    __tablename__ = "feed_runs"

    id = db.Column(db.Integer, primary_key=True)
    feed_name = db.Column(db.String(50), nullable=False)
    ran_at = db.Column(db.DateTime, default=utcnow)
    status = db.Column(db.String(20))  # success, error, skipped
    new_iocs = db.Column(db.Integer, default=0)
    updated_iocs = db.Column(db.Integer, default=0)
    message = db.Column(db.String(500))
