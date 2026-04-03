import uuid
from datetime import datetime, timezone

import bcrypt
from sqlalchemy import text


def register_or_update_endpoint(db, endpoint_info, api_key):
    """Auto-register endpoint on first POST, update heartbeat on subsequent."""
    row = db.execute(
        text("SELECT endpoint_id FROM endpoints WHERE hostname = :hostname"),
        {"hostname": endpoint_info.hostname},
    ).fetchone()

    now = datetime.now(timezone.utc)

    if row:
        endpoint_id = str(row[0])
        db.execute(
            text(
                """UPDATE endpoints
                   SET last_heartbeat = :now,
                       ip_address = :ip,
                       os = :os,
                       monitor_version = :version,
                       status = 'active'
                   WHERE endpoint_id = :eid"""
            ),
            {
                "now": now,
                "ip": endpoint_info.ip,
                "os": endpoint_info.os,
                "version": endpoint_info.monitor_version,
                "eid": endpoint_id,
            },
        )
    else:
        endpoint_id = str(uuid.uuid4())
        key_hash = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()
        db.execute(
            text(
                """INSERT INTO endpoints
                   (endpoint_id, hostname, ip_address, os, monitor_version,
                    api_key_hash, last_heartbeat, status)
                   VALUES (:eid, :hostname, :ip, :os, :version, :hash, :now, 'active')"""
            ),
            {
                "eid": endpoint_id,
                "hostname": endpoint_info.hostname,
                "ip": endpoint_info.ip,
                "os": endpoint_info.os,
                "version": endpoint_info.monitor_version,
                "hash": key_hash,
                "now": now,
            },
        )

    db.commit()
    return endpoint_id


def get_all_endpoints(db):
    """Get all registered endpoints with session and alert counts."""
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

    result = []
    for r in rows:
        result.append(
            {
                "endpoint_id": str(r.endpoint_id),
                "hostname": r.hostname,
                "ip_address": r.ip_address,
                "os": r.os,
                "monitor_version": r.monitor_version,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_heartbeat": r.last_heartbeat.isoformat()
                if r.last_heartbeat
                else None,
                "status": r.status,
                "session_count": r.session_count,
                "alert_count": r.alert_count,
            }
        )
    return result
