"""HoneyLens Dashboard API."""

from flask import Flask, jsonify, request
from flask_cors import CORS
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from shared.config import API_PORT, ALLOWED_ORIGIN, RUN_WORKER
from shared.db import init_db, query_events, get_event

app = Flask(__name__)

# Allow requests from our React frontend
CORS(app, origins=[ALLOWED_ORIGIN])


def get_all_events():
    """Fetch events for dashboard calculations."""
    return query_events(limit=10000)


def parse_date(value):
    """Convert an ISO date string into a datetime."""
    if not value:
        return None

    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)

        return date

    except (ValueError, TypeError):
        return None


# 1. Health check
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# 2. Dashboard statistics
@app.route("/api/stats", methods=["GET"])
def stats():
    events = get_all_events()

    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    ten_minutes_ago = now - timedelta(minutes=10)

    last_hour = []
    last_ten_minutes = []

    for event in events:
        created = parse_date(event.get("created_at"))

        if created:
            if created >= one_hour_ago:
                last_hour.append(event)

            if created >= ten_minutes_ago:
                last_ten_minutes.append(event)

    by_type = Counter(
        event["attack_type"]
        for event in events
        if event.get("attack_type")
    )

    by_severity = Counter(
        event["severity"]
        for event in events
        if event.get("severity")
    )

    unique_ips = {
        event["ip"] for event in events if event.get("ip")
    }

    pending = sum(
        1 for event in events
        if event.get("status") == "pending"
    )

    if any(
        event.get("severity") == "Critical"
        for event in last_ten_minutes
    ):
        threat_level = "Critical"

    elif len(last_ten_minutes) > 20:
        threat_level = "High"

    elif last_hour:
        threat_level = "Medium"

    else:
        threat_level = "Low"

    return jsonify({
        "total": len(events),
        "last_hour": len(last_hour),
        "unique_ips": len(unique_ips),
        "pending": pending,
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "threat_level": threat_level
    })


# 3. Get events with optional filters
@app.route("/api/events", methods=["GET"])
def events_list():
    try:
        limit = max(1, min(request.args.get("limit", 50, type=int), 500))
        since_id = request.args.get("since_id", type=int)

        events = query_events(
            limit=limit,
            since_id=since_id,
            severity=request.args.get("severity") or None,
            attack_type=request.args.get("attack_type") or None,
            ip=request.args.get("ip") or None
        )

        return jsonify({"events": events})

    except Exception:
        return jsonify({"error": "Unable to fetch events"}), 500


# 4. Get one event by ID
@app.route("/api/events/<int:event_id>", methods=["GET"])
def event_detail(event_id):
    event = get_event(event_id)

    if event is None:
        return jsonify({"error": "Event not found"}), 404

    return jsonify(event)


# 5. Attack timeline
@app.route("/api/timeline", methods=["GET"])
def timeline():
    minutes = max(1, min(request.args.get("minutes", 60, type=int), 1440))
    bucket = max(1, min(request.args.get("bucket", 2, type=int), 60))

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=minutes)

    events = get_all_events()
    buckets = defaultdict(int)

    for event in events:
        created = parse_date(event.get("created_at"))

        if created and start_time <= created <= now:
            elapsed = (created - start_time).total_seconds() / 60
            bucket_number = int(elapsed // bucket)

            bucket_start = start_time + timedelta(
                minutes=bucket_number * bucket
            )

            buckets[bucket_start] += 1

    points = [
        {
            "t": timestamp.isoformat().replace("+00:00", "Z"),
            "count": count
        }
        for timestamp, count in sorted(buckets.items())
    ]

    return jsonify({"points": points})


# 6. Top attackers
@app.route("/api/attackers", methods=["GET"])
def attackers():
    limit = max(1, min(request.args.get("limit", 10, type=int), 100))

    events = get_all_events()
    grouped = defaultdict(list)

    for event in events:
        ip = event.get("ip")

        if ip:
            grouped[ip].append(event)

    results = []

    for ip, ip_events in grouped.items():
        types = Counter(
            event["attack_type"]
            for event in ip_events
            if event.get("attack_type")
        )

        results.append({
            "ip": ip,
            "country": next(
                (e.get("country") for e in ip_events if e.get("country")),
                None
            ),
            "count": len(ip_events),
            "top_type": types.most_common(1)[0][0] if types else "Unknown"
        })

    results.sort(key=lambda item: item["count"], reverse=True)

    return jsonify({"attackers": results[:limit]})


# 7. Attack map locations
@app.route("/api/geo", methods=["GET"])
def geo_points():
    events = get_all_events()
    grouped = {}

    for event in events:
        ip = event.get("ip")
        lat = event.get("lat")
        lon = event.get("lon")

        if not ip or lat is None or lon is None:
            continue

        if ip not in grouped:
            grouped[ip] = {
                "ip": ip,
                "lat": lat,
                "lon": lon,
                "country": event.get("country"),
                "count": 0
            }

        grouped[ip]["count"] += 1

    return jsonify({"points": list(grouped.values())})


# 8. MITRE statistics
@app.route("/api/mitre", methods=["GET"])
def mitre_stats():
    events = get_all_events()
    grouped = defaultdict(lambda: {"name": None, "count": 0})

    for event in events:
        mitre_id = event.get("mitre_id")

        if not mitre_id:
            continue

        grouped[mitre_id]["name"] = event.get("mitre_name")
        grouped[mitre_id]["count"] += 1

    items = [
        {
            "mitre_id": mitre_id,
            "name": values["name"],
            "count": values["count"]
        }
        for mitre_id, values in grouped.items()
    ]

    items.sort(key=lambda item: item["count"], reverse=True)

    return jsonify({"items": items})


# 9. Generate an incident report for an IP
@app.route("/api/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")

    if not isinstance(ip, str) or not ip.strip():
        return jsonify({"error": "A valid IP is required"}), 400

    ip = ip.strip()

    events = [
        event for event in get_all_events()
        if event.get("ip") == ip
    ]

    if not events:
        return jsonify({
            "ip": ip,
            "report": "No events found for this IP address."
        })

    try:
        from ai.llm_client import generate_report
        report_text = generate_report(events)
    except Exception as exc:
        types = Counter(
            event["attack_type"]
            for event in events
            if event.get("attack_type")
        )

        severities = Counter(
            event["severity"]
            for event in events
            if event.get("severity")
        )

        report_text = (
            f"Incident Report for IP: {ip}\n"
            f"Total events: {len(events)}\n"
            f"Attack types: {dict(types)}\n"
            f"Severity distribution: {dict(severities)}\n"
            f"Country: {next((e.get('country') for e in events if e.get('country')), 'Unknown')}\n"
            f"Latest event: {events[0].get('created_at')}\n"
        )

    return jsonify({
        "ip": ip,
        "report": report_text
    })


def _bootstrap():
    """Ensure DB tables exist and background worker starts under WSGI/Gunicorn and CLI."""
    try:
        init_db()
    except Exception as exc:
        print(f"[api] init_db warning: {exc}")

    if RUN_WORKER:
        try:
            from pipeline import worker
            if hasattr(worker, "start"):
                worker.start()
        except Exception as exc:
            print(f"[api] pipeline worker start warning: {exc}")


_bootstrap()

# Start the API
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT, debug=False)
