# Watchdesk — Custom Threat Intelligence Platform

A self-hosted CTI platform that pulls indicators of compromise (IOCs) from
open threat feeds, correlates them across sources, and shows them on a live
dashboard. Built as a portfolio project to demonstrate the core CTI pipeline
a SOC analyst works with every day: **collect → normalize → correlate → triage**.

## What it does

- Pulls IOCs (IPs, domains, URLs, hashes) from three feeds on a schedule:
  - **[ThreatFox](https://threatfox.abuse.ch/)** (abuse.ch) — malware C2 infrastructure, no key required
  - **[URLhaus](https://urlhaus.abuse.ch/)** (abuse.ch) — malicious URLs, no key required
  - **[AbuseIPDB](https://www.abuseipdb.com/)** — reported abusive IPs, free API key required
- Normalizes every feed's format into one schema (`type`, `value`, `threat_type`,
  `malware_family`, `confidence`, `severity`, `sources`, `reference`)
- **Correlates**: if the same indicator shows up in 2+ independent feeds, it's
  automatically marked "corroborated" and its severity is raised — this is the
  actual analytical value a TIP adds over just reading raw feeds
- Dashboard with search/filter by type and severity, a feed-health panel, and
  a manual "Refresh feeds" button
- Runs indefinitely: a background scheduler re-pulls every 30 minutes (configurable)

## Architecture

```
feeds/threatfox.py  ─┐
feeds/urlhaus.py    ─┼─► ingest.py (normalize + correlate) ─► SQLite (models.py) ─► routes.py (JSON API) ─► dashboard.html/app.js
feeds/abuseipdb.py  ─┘
```

Each feed module knows nothing about the others or about storage — it just
returns a list of dicts in a common shape. `ingest.py` is the only place that
does correlation logic, and `FeedRun` records give you an audit trail of every
pull (success/error/skipped, how many new IOCs, when). That separation is
what makes it easy to add a fourth or fifth feed later without touching
anything else.

## Running it

### Option A — Docker (recommended)

```bash
cp .env.example .env
# edit .env and add your AbuseIPDB key if you have one (optional)
docker compose up --build
```

Visit http://localhost:5000

### Option B — Local Python

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

## Getting a free AbuseIPDB key (optional but recommended)

1. Create a free account at https://www.abuseipdb.com/register
2. Go to https://www.abuseipdb.com/account/api and generate a key
3. Paste it into `.env` as `ABUSEIPDB_API_KEY=...`

Without it, the dashboard still works fully — that feed just shows as
"skipped" in the feed-health panel instead of erroring.

## Extending it

To add a new feed:
1. Create `app/feeds/yourfeed.py` with a `fetch()` function returning a list
   of dicts shaped like the existing feeds (`ioc_type`, `value`, `threat_type`,
   `malware_family`, `confidence`, `reference`, `source`)
2. Add it to the `FEEDS` list in `app/ingest.py`
3. Done — correlation, storage, and the dashboard pick it up automatically

Ideas for a next iteration: MITRE ATT&CK tagging, CSV/STIX export, Slack/email
alerting on new critical IOCs, or a "watchlist" of your own assets to flag
matches against.

## Why this is worth having on a resume / talking about in interviews

This project touches the same concepts a TIP (Threat Intelligence Platform)
like MISP or OpenCTI is built around, at a scale you can fully explain:
- **Feed ingestion & normalization** — different vendors format IOCs differently;
  reconciling that into one schema is real day-1 SOC/CTI work
- **Correlation & confidence scoring** — why an indicator seen in two
  independent sources is more actionable than one seen in a single feed
- **Operational resilience** — a feed failing (bad key, rate limit, feed
  down) doesn't take down the whole pipeline; it's logged and skipped
- **Triage-first UI** — severity and corroboration are the first things a
  SOC analyst needs to see, not buried in a raw table

Be ready to explain the correlation logic (`ingest.py`) and the schema
decisions (`models.py`) specifically — those two files are where the actual
design thinking lives, and that's usually what an interviewer will ask about.
