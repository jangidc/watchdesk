import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
scheduler = BackgroundScheduler(daemon=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("threatintel")


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        app.instance_path, "threatintel.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from app import models  # noqa: F401
    from app.routes import bp as main_bp

    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()

    _start_scheduler(app)

    return app


def _start_scheduler(app):
    """Wire up periodic feed pulls. Runs once at boot, then on an interval."""
    from app.ingest import run_all_feeds

    refresh_minutes = int(os.getenv("FEED_REFRESH_MINUTES", "30"))

    def job():
        with app.app_context():
            run_all_feeds()

    # Guard against Flask's debug-mode reloader starting this twice: when the
    # reloader is active, the first (monitor) process has no WERKZEUG_RUN_MAIN
    # set, only the actual serving child process does.
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    if not scheduler.running:
        scheduler.add_job(
            job,
            "interval",
            minutes=refresh_minutes,
            id="feed_refresh",
            next_run_time=None,  # first run triggered manually below to avoid double-run on reload
        )
        scheduler.start()
        # Kick off an initial pull shortly after boot so the dashboard isn't empty.
        scheduler.modify_job("feed_refresh", next_run_time=None)
        import threading

        threading.Timer(2.0, job).start()
