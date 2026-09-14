from flask import Blueprint, render_template, request, jsonify
from sqlalchemy import func
from app import db
from app.models import IOC, FeedRun
from app.ingest import run_all_feeds

bp = Blueprint("main", __name__)


@bp.route("/")
def dashboard():
    return render_template("dashboard.html")


@bp.route("/api/stats")
def api_stats():
    total = IOC.query.count()
    by_type = dict(
        db.session.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all()
    )
    by_severity = dict(
        db.session.query(IOC.severity, func.count(IOC.id)).group_by(IOC.severity).all()
    )
    corroborated = IOC.query.filter(IOC.source_count >= 2).count()

    latest_runs = {}
    for run in FeedRun.query.order_by(FeedRun.ran_at.desc()).limit(50).all():
        if run.feed_name not in latest_runs:
            latest_runs[run.feed_name] = {
                "status": run.status,
                "ran_at": run.ran_at.isoformat() if run.ran_at else None,
                "message": run.message,
                "new_iocs": run.new_iocs,
            }

    return jsonify(
        {
            "total": total,
            "corroborated": corroborated,
            "by_type": by_type,
            "by_severity": by_severity,
            "feeds": latest_runs,
        }
    )


@bp.route("/api/iocs")
def api_iocs():
    query = IOC.query

    ioc_type = request.args.get("type")
    severity = request.args.get("severity")
    search = request.args.get("q")
    source = request.args.get("source")

    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    if severity:
        query = query.filter(IOC.severity == severity)
    if source:
        query = query.filter(IOC.sources.like(f"%{source}%"))
    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(
                IOC.value.like(like),
                IOC.malware_family.like(like),
                IOC.threat_type.like(like),
            )
        )

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    query = query.order_by(IOC.last_seen.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify(
        {
            "items": [i.to_dict() for i in pagination.items],
            "page": pagination.page,
            "pages": pagination.pages,
            "total": pagination.total,
        }
    )


@bp.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Manual trigger for the 'Refresh Now' button on the dashboard."""
    run_all_feeds()
    return jsonify({"status": "ok"})
