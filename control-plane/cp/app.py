from fastapi import Depends, FastAPI

from cp.auth import validate_api_key
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


@app.post("/api/v1/ingest", response_model=IngestResponse)
async def ingest(
    payload: IngestRequest,
    api_key: str = Depends(validate_api_key),
    db=Depends(get_db),
):
    """Receive monitoring data from a client endpoint."""
    endpoint_id = register_or_update_endpoint(db, payload.endpoint, api_key)
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
