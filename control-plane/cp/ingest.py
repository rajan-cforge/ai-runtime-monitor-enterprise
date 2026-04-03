import json

from sqlalchemy import text


def process_ingest(db, endpoint_id, payload):
    """Process an ingest payload from a client endpoint."""
    stored = {"sessions": 0, "events": 0, "api_calls": 0, "alerts": 0}

    # UPSERT sessions
    for s in payload.sessions:
        db.execute(
            text(
                """INSERT INTO fleet_sessions
                   (endpoint_id, client_session_id, start_time, cwd, model,
                    agent_type, title, total_input_tokens, total_output_tokens,
                    total_turns, total_cost, last_activity)
                   VALUES (:eid, :sid, :start, :cwd, :model, :atype, :title,
                           :inp, :outp, :turns, :cost, :last)
                   ON CONFLICT (endpoint_id, client_session_id) DO UPDATE SET
                       model = COALESCE(EXCLUDED.model, fleet_sessions.model),
                       agent_type = COALESCE(EXCLUDED.agent_type, fleet_sessions.agent_type),
                       title = COALESCE(EXCLUDED.title, fleet_sessions.title),
                       total_input_tokens = EXCLUDED.total_input_tokens,
                       total_output_tokens = EXCLUDED.total_output_tokens,
                       total_turns = EXCLUDED.total_turns,
                       total_cost = EXCLUDED.total_cost,
                       last_activity = EXCLUDED.last_activity"""
            ),
            {
                "eid": endpoint_id,
                "sid": s.client_session_id,
                "start": s.start_time,
                "cwd": s.cwd,
                "model": s.model,
                "atype": s.agent_type,
                "title": s.title,
                "inp": s.total_input_tokens,
                "outp": s.total_output_tokens,
                "turns": s.total_turns,
                "cost": s.total_cost,
                "last": s.last_activity,
            },
        )
        stored["sessions"] += 1

    # INSERT events (dedup via UNIQUE constraint)
    for e in payload.events:
        try:
            db.execute(
                text(
                    """INSERT INTO fleet_events
                       (endpoint_id, client_event_id, timestamp, session_id,
                        event_type, source_layer, data_json)
                       VALUES (:eid, :cid, :ts, :sid, :etype, :src, :data)
                       ON CONFLICT (endpoint_id, client_event_id) DO NOTHING"""
                ),
                {
                    "eid": endpoint_id,
                    "cid": e.client_event_id,
                    "ts": e.timestamp,
                    "sid": e.session_id,
                    "etype": e.event_type,
                    "src": e.source_layer,
                    "data": json.dumps(e.data_json),
                },
            )
            stored["events"] += 1
        except Exception:
            continue

    # INSERT api_calls (dedup)
    for c in payload.api_calls:
        try:
            db.execute(
                text(
                    """INSERT INTO fleet_api_calls
                       (endpoint_id, client_call_id, timestamp, session_id,
                        model, destination_service, input_tokens, output_tokens,
                        cache_read_tokens, cache_write_tokens,
                        estimated_cost_usd, latency_ms)
                       VALUES (:eid, :cid, :ts, :sid, :model, :svc,
                               :inp, :outp, :cr, :cw, :cost, :lat)
                       ON CONFLICT (endpoint_id, client_call_id) DO NOTHING"""
                ),
                {
                    "eid": endpoint_id,
                    "cid": c.client_call_id,
                    "ts": c.timestamp,
                    "sid": c.session_id,
                    "model": c.model,
                    "svc": c.destination_service,
                    "inp": c.input_tokens,
                    "outp": c.output_tokens,
                    "cr": c.cache_read_tokens,
                    "cw": c.cache_write_tokens,
                    "cost": c.estimated_cost_usd,
                    "lat": c.latency_ms,
                },
            )
            stored["api_calls"] += 1
        except Exception:
            continue

    # Denormalize alerts
    for a in payload.alerts:
        try:
            db.execute(
                text(
                    """INSERT INTO fleet_alerts
                       (endpoint_id, client_event_id, timestamp, session_id,
                        severity, patterns, context, snippet, validated, confidence)
                       VALUES (:eid, :cid, :ts, :sid, :sev, :pats,
                               :ctx, :snip, :val, :conf)
                       ON CONFLICT (endpoint_id, client_event_id) DO NOTHING"""
                ),
                {
                    "eid": endpoint_id,
                    "cid": a.client_event_id,
                    "ts": a.timestamp,
                    "sid": a.session_id,
                    "sev": a.severity,
                    "pats": a.patterns,
                    "ctx": a.context,
                    "snip": a.snippet,
                    "val": a.validated,
                    "conf": a.confidence,
                },
            )
            stored["alerts"] += 1
        except Exception:
            continue

    # Update watermarks
    for table_name, last_id in payload.watermarks.items():
        db.execute(
            text(
                """INSERT INTO sync_watermarks (endpoint_id, table_name, last_client_id, last_sync)
                   VALUES (:eid, :tbl, :lid, now())
                   ON CONFLICT (endpoint_id, table_name) DO UPDATE SET
                       last_client_id = EXCLUDED.last_client_id,
                       last_sync = now()"""
            ),
            {"eid": endpoint_id, "tbl": table_name, "lid": last_id},
        )

    db.commit()
    return stored
