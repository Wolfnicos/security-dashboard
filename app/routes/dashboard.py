"""Dashboard routes — serves the main UI and JSON API endpoints."""

from flask import Blueprint, render_template, jsonify
from app.models.database import get_connection, init_db
from app.services.geolocation import geolocate_ips

dashboard_bp = Blueprint("dashboard", __name__)


def _query_alerts():
    """Fetch all alerts from the database."""
    conn = get_connection()
    init_db(conn)
    cur = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@dashboard_bp.route("/")
def index():
    alerts = _query_alerts()

    # Summary cards
    total_attacks = len(alerts)
    unique_ips = len({a["ip"] for a in alerts})
    critical_count = sum(1 for a in alerts if a["severity"] == "critical")
    high_count = sum(1 for a in alerts if a["severity"] == "high")

    # Parse attempt counts from details field ("22 failures in window | 22 total | ...")
    total_attempts = 0
    for a in alerts:
        if a["details"]:
            parts = a["details"].split("|")
            for p in parts:
                if "total" in p:
                    try:
                        total_attempts += int(p.strip().split()[0])
                    except (ValueError, IndexError):
                        pass

    detection_rate = round((total_attacks / max(total_attempts, 1)) * 100, 1)

    # Attacks per hour
    hourly = {}
    for a in alerts:
        try:
            hour = a["timestamp"][:13]  # "2026-02-26T06"
            hourly[hour] = hourly.get(hour, 0) + 1
        except (TypeError, IndexError):
            pass
    hourly_sorted = sorted(hourly.items())
    hourly_labels = [h[0].replace("T", " ") + ":00" for h in hourly_sorted]
    hourly_values = [h[1] for h in hourly_sorted]

    # Severity distribution
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1

    # Top 10 attackers
    ip_stats = {}
    for a in alerts:
        ip = a["ip"]
        if ip not in ip_stats:
            ip_stats[ip] = {
                "ip": ip,
                "count": 0,
                "severity": a["severity"],
                "timestamp": a["timestamp"],
                "details": a["details"],
            }
        ip_stats[ip]["count"] += 1
        # Keep the highest severity
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if sev_order.get(a["severity"], 0) > sev_order.get(ip_stats[ip]["severity"], 0):
            ip_stats[ip]["severity"] = a["severity"]

    top_attackers = sorted(ip_stats.values(), key=lambda x: x["count"], reverse=True)[:10]

    return render_template(
        "index.html",
        total_attacks=total_attacks,
        unique_ips=unique_ips,
        critical_count=critical_count,
        high_count=high_count,
        total_attempts=total_attempts,
        detection_rate=detection_rate,
        hourly_labels=hourly_labels,
        hourly_values=hourly_values,
        sev_counts=sev_counts,
        top_attackers=top_attackers,
        alerts=alerts,
    )


@dashboard_bp.route("/api/stats")
def api_stats():
    """Health check endpoint — returns basic alert stats as JSON."""
    alerts = _query_alerts()
    return jsonify({
        "status": "healthy",
        "total_alerts": len(alerts),
        "unique_ips": len({a["ip"] for a in alerts}),
    })


@dashboard_bp.route("/api/geo")
def api_geo():
    """Return geolocation data for all alert IPs."""
    alerts = _query_alerts()
    ips = list({a["ip"] for a in alerts})
    geo_data = geolocate_ips(ips)

    # Merge with alert info
    features = []
    ip_severity = {}
    for a in alerts:
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        current = sev_order.get(ip_severity.get(a["ip"], "low"), 0)
        new = sev_order.get(a["severity"], 0)
        if new > current:
            ip_severity[a["ip"]] = a["severity"]

    for ip, geo in geo_data.items():
        if geo["lat"] == 0 and geo["lon"] == 0:
            continue
        features.append({
            "ip": ip,
            "lat": geo["lat"],
            "lon": geo["lon"],
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"],
            "severity": ip_severity.get(ip, "low"),
        })

    return jsonify(features)
