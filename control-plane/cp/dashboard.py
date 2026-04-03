from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from cp.db import get_db

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
async def fleet_dashboard():
    """Serve the fleet dashboard HTML."""
    html_path = Path(__file__).parent.parent / "fleet_dashboard.html"
    if not html_path.exists():
        html_path = Path(__file__).parent / "fleet_dashboard.html"
    if not html_path.exists():
        return HTMLResponse("<h1>Fleet dashboard not found</h1>", status_code=404)
    return HTMLResponse(html_path.read_text())


@router.get("/api/v1/fleet/stats")
async def fleet_stats(db=Depends(get_db)):
    """Aggregated fleet statistics."""
    stats = {}

    row = db.execute(
        text("SELECT COUNT(*) FROM endpoints WHERE status = 'active'")
    ).fetchone()
    stats["total_endpoints"] = row[0]

    row = db.execute(
        text(
            """SELECT COUNT(*),
                      COALESCE(SUM(total_input_tokens), 0),
                      COALESCE(SUM(total_output_tokens), 0),
                      COALESCE(SUM(total_cost), 0)
               FROM fleet_sessions"""
        )
    ).fetchone()
    stats["total_sessions"] = row[0]
    stats["total_input_tokens"] = int(row[1])
    stats["total_output_tokens"] = int(row[2])
    stats["total_cost"] = float(row[3])

    row = db.execute(text("SELECT COUNT(*) FROM fleet_events")).fetchone()
    stats["total_events"] = row[0]

    row = db.execute(
        text("SELECT COUNT(*) FROM fleet_alerts WHERE dismissed = false")
    ).fetchone()
    stats["total_alerts"] = row[0]

    # Alert severity breakdown
    sev_rows = db.execute(
        text(
            """SELECT severity, COUNT(*)
               FROM fleet_alerts WHERE dismissed = false
               GROUP BY severity"""
        )
    ).fetchall()
    stats["alert_severity"] = {r[0]: r[1] for r in sev_rows}

    # Model usage
    model_rows = db.execute(
        text(
            """SELECT model, COUNT(*) AS cnt
               FROM fleet_sessions WHERE model IS NOT NULL
               GROUP BY model ORDER BY cnt DESC LIMIT 10"""
        )
    ).fetchall()
    stats["model_usage"] = [{"model": r[0], "count": r[1]} for r in model_rows]

    return stats


@router.get("/api/v1/fleet/sessions")
async def fleet_sessions(
    db=Depends(get_db),
    limit: int = 100,
    endpoint_id: str = None,
    agent_type: str = None,
):
    """Fleet sessions with endpoint info."""
    query = """SELECT fs.*, e.hostname, e.ip_address
               FROM fleet_sessions fs
               JOIN endpoints e ON fs.endpoint_id = e.endpoint_id
               WHERE 1=1"""
    params: dict = {}
    if endpoint_id:
        query += " AND fs.endpoint_id = :eid"
        params["eid"] = endpoint_id
    if agent_type:
        query += " AND fs.agent_type = :atype"
        params["atype"] = agent_type
    query += " ORDER BY fs.last_activity DESC NULLS LAST LIMIT :limit"
    params["limit"] = limit

    rows = db.execute(text(query), params).fetchall()
    return [dict(r._mapping) for r in rows]


@router.get("/api/v1/fleet/endpoints")
async def fleet_endpoints(db=Depends(get_db)):
    """Fleet endpoints for the dashboard (no auth required)."""
    rows = db.execute(
        text(
            """SELECT e.endpoint_id, e.hostname, e.ip_address, e.os,
                      e.monitor_version, e.first_seen, e.last_heartbeat, e.status,
                      COALESCE(s.session_count, 0) AS session_count,
                      COALESCE(a.alert_count, 0) AS alert_count
               FROM endpoints e
               LEFT JOIN (
                   SELECT endpoint_id, COUNT(*) AS session_count
                   FROM fleet_sessions GROUP BY endpoint_id
               ) s ON e.endpoint_id = s.endpoint_id
               LEFT JOIN (
                   SELECT endpoint_id, COUNT(*) AS alert_count
                   FROM fleet_alerts WHERE dismissed = false
                   GROUP BY endpoint_id
               ) a ON e.endpoint_id = a.endpoint_id
               ORDER BY e.last_heartbeat DESC NULLS LAST"""
        )
    ).fetchall()
    return [
        {
            "endpoint_id": str(r.endpoint_id),
            "hostname": r.hostname,
            "ip_address": r.ip_address or "",
            "os": r.os or "",
            "monitor_version": r.monitor_version or "",
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_heartbeat": r.last_heartbeat.isoformat() if r.last_heartbeat else None,
            "status": r.status,
            "session_count": r.session_count,
            "alert_count": r.alert_count,
        }
        for r in rows
    ]


@router.get("/api/v1/fleet/alerts")
async def fleet_alerts(
    db=Depends(get_db),
    limit: int = 100,
    severity: str = None,
    include_dismissed: bool = False,
):
    """Fleet alerts across all endpoints."""
    query = """SELECT fa.*, e.hostname
               FROM fleet_alerts fa
               JOIN endpoints e ON fa.endpoint_id = e.endpoint_id
               WHERE 1=1"""
    params: dict = {}
    if not include_dismissed:
        query += " AND fa.dismissed = false"
    if severity:
        query += " AND fa.severity = :sev"
        params["sev"] = severity
    query += " ORDER BY fa.timestamp DESC LIMIT :limit"
    params["limit"] = limit

    rows = db.execute(text(query), params).fetchall()
    return [dict(r._mapping) for r in rows]
