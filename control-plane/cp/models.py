from typing import Optional

from pydantic import BaseModel, Field


class EndpointInfo(BaseModel):
    hostname: str
    os: str = ""
    ip: str = ""
    monitor_version: str = ""


class SessionPayload(BaseModel):
    client_session_id: str
    start_time: Optional[str] = None
    cwd: Optional[str] = None
    model: Optional[str] = None
    agent_type: Optional[str] = None
    title: Optional[str] = None
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_turns: int = 0
    total_cost: float = 0
    last_activity: Optional[str] = None


class EventPayload(BaseModel):
    client_event_id: int
    timestamp: str
    session_id: Optional[str] = None
    event_type: str
    source_layer: str = "jsonl"
    data_json: dict = Field(default_factory=dict)


class ApiCallPayload(BaseModel):
    client_call_id: int
    timestamp: str
    session_id: Optional[str] = None
    model: Optional[str] = None
    destination_service: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    estimated_cost_usd: float = 0
    latency_ms: int = 0


class AlertPayload(BaseModel):
    client_event_id: int
    timestamp: str
    session_id: Optional[str] = None
    severity: str = "medium"
    patterns: list[str] = Field(default_factory=list)
    context: Optional[str] = None
    snippet: Optional[str] = None
    validated: bool = False
    confidence: Optional[str] = None


class IngestRequest(BaseModel):
    endpoint: EndpointInfo
    sessions: list[SessionPayload] = Field(default_factory=list)
    events: list[EventPayload] = Field(default_factory=list)
    api_calls: list[ApiCallPayload] = Field(default_factory=list)
    alerts: list[AlertPayload] = Field(default_factory=list)
    watermarks: dict = Field(default_factory=dict)


class IngestResponse(BaseModel):
    stored: dict
    endpoint_id: str
    next_sync_after: int = 30
