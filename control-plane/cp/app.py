from __future__ import annotations

from fastapi import Depends, FastAPI, Header

from cp.auth import validate_api_key, verify_endpoint_key
from cp.dashboard import router as dashboard_router
from cp.db import get_db
from cp.ingest import process_ingest
from cp.models import IngestRequest, IngestResponse
from cp.registry import get_all_endpoints, register_or_update_endpoint

app = FastAPI(title="AI Runtime Monitor — Control Plane", version="0.1.0")

# Include dashboard routes. The /dashboard HTML shell is unauthenticated
# (it's a static SPA that prompts for the key), but every
# /api/v1/fleet/* route below it now requires X-API-Key (P1-03).
app.include_router(dashboard_router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/ingest", response_model=IngestResponse, status_code=202)
async def ingest(
    payload: IngestRequest,
    api_key: str = Depends(validate_api_key),
    x_endpoint_key: str | None = Header(default=None),
    db=Depends(get_db),
):
    """Receive monitoring data from a client endpoint.

    Two layers of auth (per audit C1):
    * Fleet-wide ``X-API-Key`` — proves the request came from a sanctioned
      monitor binary.
    * Per-endpoint ``X-Endpoint-Key`` — verified against the bcrypt hash
      in ``endpoints.api_key_hash`` so individual endpoints can be
      rotated or revoked without churning the fleet secret.
    """
    verify_endpoint_key(db, payload.endpoint.hostname, x_endpoint_key)
    endpoint_id = register_or_update_endpoint(db, payload.endpoint, x_endpoint_key)
    stored = process_ingest(db, endpoint_id, payload)
    return IngestResponse(
        stored=stored,
        endpoint_id=endpoint_id,
        next_sync_after=30,
    )


@app.get("/api/v1/endpoints")
async def endpoints(
    api_key: str = Depends(validate_api_key),
    db=Depends(get_db),
):
    """List all registered endpoints."""
    return get_all_endpoints(db)
