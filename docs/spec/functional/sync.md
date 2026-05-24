# Functional Spec — sync.py

**Module:** `src/claude_monitoring/sync.py`
**Status:** v0.2 launch candidate
**Audit history:** P0-01, P1-04, C1, C3

## 1. Purpose

`sync.py` is the client-side bridge between the local daemon and the GoCloudForge control plane. It runs as a background thread that periodically reads new data from the local `monitor.db`, sanitizes it for sensitive content, and POSTs it to the control plane's ingest endpoint.

The module exists to enable fleet-scale visibility. A solo developer running Vigil locally has no need for `sync.py`. A team or organization that wants centralized visibility across multiple developer endpoints uses the control plane, and `sync.py` is what gets data there.

## 2. Public contract

### 2.1 SyncAgent class

```python
class SyncAgent:
    def __init__(
        self,
        cp_url: str,
        api_key: str,
        interval: int = 30,
        endpoint_key: str | None = None,
    ) -> None:
        """Create a sync agent ready to start.
        
        cp_url: Control plane base URL (e.g., https://cp.gocloudforge.com)
        api_key: Fleet-level API key (per-organization)
        interval: Seconds between sync cycles
        endpoint_key: Per-endpoint key for auth. Falls back to api_key if None.
        """
    
    def start(self) -> threading.Thread:
        """Start the sync loop in a daemon thread. Returns the Thread."""
    
    def stop(self) -> None:
        """Signal the sync loop to exit at the next cycle boundary."""
```

### 2.2 Sanitization helpers (private but tested directly)

```python
def _sanitize_string(value: Any) -> str:
    """Mask credentials in a string. Returns '' on any failure (sentinel).
    
    Audit C3 contract:
    - non-string input → '' + warning
    - oversized input → truncated to _MAX_SANITIZE_LEN
    - control characters stripped
    - any exception → '' + warning (never raw value)
    """

def _sanitize_payload(obj: Any) -> Any:
    """Recursively walk payload, mask fields in _SANITIZE_TEXT_FIELDS.
    
    Other fields pass through unchanged.
    """
```

## 3. Inputs

- **Configuration:** `cp_url`, `api_key`, `endpoint_key`, `interval` — provided by the caller (typically `monitor.py` when `--sync` is enabled)
- **Local database:** read from `~/claude_watch_output/monitor.db` via `config.get_db_path()`
- **Watermark table:** `sync_state` table tracks last synced ID per source table (created on first sync if absent)
- **Hostname / OS info:** `socket.gethostname()` and `platform.system()` for endpoint identification

## 4. Outputs

- **HTTP POST requests:** to `{cp_url}/api/v1/ingest` with JSON body
- **Database updates:** watermarks in `sync_state` are advanced after each successful sync
- **Local logging:** info messages on successful syncs, warnings on sanitization failures, errors on transport failures (with exponential backoff applied)

## 5. Side effects

- **Network I/O:** outbound HTTPS to the control plane URL
- **Database mutation:** UPDATEs to `sync_state` after successful sync; no reads/writes to event data itself
- **No file system mutation outside the database**
- **No process creation**

## 6. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| Control plane unreachable | Sync cycle fails, retries with exponential backoff (1s → 60s cap) | Auto-recovers when network returns |
| Control plane returns 4xx | Sync cycle logs the error, retries (server-side issue) | Manual: check API key / endpoint key validity |
| Control plane returns 5xx | Same as unreachable: backoff and retry | Auto-recovers when server is back |
| Local DB locked | Single retry, then back off to next cycle | Auto-recovers when concurrent operation completes |
| Sanitization fails | Field set to '' (fail-closed sentinel); warning logged | Continues; sanitization failure does NOT block the sync |
| Watermark advance fails | DB write retried inside the same cycle | If persistent: sync stops; user must investigate manually |

The exponential backoff is bounded at 60 seconds. After many consecutive failures, the agent keeps trying at 60s intervals forever (no permanent failure state).

## 7. Audit history (extensive — this module is security-critical)

### 7.1 P0-01: watermark advance was wrong

**Original code:**
```python
new_sessions = self._read_sessions(conn, watermarks.get("sessions", 0))
# ... later ...
watermarks["sessions"] += len(new_sessions)
```

The `_read_sessions` query was `ORDER BY rowid LIMIT 100` with no WHERE clause. It ignored the watermark entirely and re-sent the first 100 rowids on every sync. Any sessions after rowid 100 were invisible to the control plane.

**Fix:**
```python
new_sessions, sessions_max_id = self._read_sessions(conn, watermarks.get("sessions", 0))
# query now: WHERE rowid > ? ORDER BY rowid LIMIT 100
# watermark advances to max_rowid seen, not previous + len()
```

Each `_read_*` helper now returns `(rows, max_id_seen)`. The watermark advances to `max_id_seen`, which correctly handles rowid gaps (deleted rows, INSERT OR IGNORE paths).

### 7.2 P1-04: sanitization at the sync boundary

Historical DB rows from before the masking fix (Phase 3A C3) might contain plaintext credentials. The sync agent must not blindly trust the local DB. `_sanitize_payload` walks every outbound payload as defense-in-depth.

The sanitization is targeted: only fields in `_SANITIZE_TEXT_FIELDS` are scanned. Non-text fields (numbers, IDs, timestamps, model names) pass through unchanged so the control plane still gets useful telemetry.

### 7.3 C1: endpoint key over the wire

Audit revealed that the original sync agent used only the fleet `api_key` for authentication. The control plane couldn't distinguish between two endpoints in the same org sending data — both would authenticate the same way.

**Fix:** Added the `endpoint_key` parameter. The control plane verifies the endpoint key against a bcrypt hash in the `endpoints.api_key_hash` column. First sync from a new endpoint key registers the endpoint with that hash. Admins can rotate keys later by passing `--cp-endpoint-key`.

### 7.4 C3: sanitizer fail-closed

The original `_sanitize_string`:
```python
try:
    # mask credentials
    return masked
except Exception:
    return value  # fail-OPEN: raw value returned!
```

A malformed legacy row could crash the masker, and the function would return the raw plaintext to the caller. The caller (`_sanitize_payload`) then transmitted plaintext to the control plane.

**Fix:** Fail-closed with sentinel:
```python
def _sanitize_string(value) -> str:
    if not isinstance(value, str):
        logger.warning(...)
        return ""  # sentinel
    try:
        # ... masking ...
    except Exception as e:
        logger.warning("sanitize failed: %s", type(e).__name__)
        return ""  # sentinel, never raw value
```

Callers must treat `""` as the failure sentinel.

The fix also added:
- Control character stripping (ASCII 0-31 except tab/newline/return, plus 127)
- Truncation to `_MAX_SANITIZE_LEN` (5000 chars)
- Log line never echoes the input

## 8. Hot-path notes

`SyncAgent._sync_loop` runs every `interval` seconds (default 30). Patterns to preserve:

- Each cycle uses a fresh DB connection (no long-held connections that could lock writes)
- `_sanitize_payload` walks the payload once (recursive but bounded by payload size)
- `requests.post` is synchronous — sync cycles do not overlap

The `interval` parameter is configurable but should not go below 10 seconds without measuring control-plane impact. v0.2 default of 30s is comfortable for the control plane's planned capacity.

## 9. Extension points

- **New event types:** add the type to `_read_events` (already generic — reads any event type)
- **New sanitization fields:** add the field name to `_SANITIZE_TEXT_FIELDS`
- **New transport (e.g., gRPC, websocket):** would require subclassing `SyncAgent` with a different `_do_sync` implementation
- **New retry policy:** override `_sync_loop` to use a different backoff strategy

## 10. Testing

- **Unit tests:** `tests/test_sync.py` covers `_sanitize_string` and `_sanitize_payload` with adversarial inputs (None, bytes, ints, lists, control characters, oversized input)
- **Watermark advance:** test confirms watermark advances to max_id, not previous + len
- **Sanitization defense-in-depth:** synthetic plaintext credentials in payload assert they're masked at the boundary
- **Fail-closed verification:** induced exceptions in the masker verify sentinel is returned, not raw value

## 11. Dependencies

- Standard library: `json`, `logging`, `platform`, `socket`, `sqlite3`, `threading`
- Project modules: `config`, `utils`, `security` (for `mask_value`)
- Third-party: `requests` (HTTP client)

## 12. Future direction

- **gRPC transport (v0.3):** lower-latency than HTTPS+JSON, better for high-volume endpoints
- **Compression (v0.3):** gzip or brotli for payloads > 10KB
- **Configurable batching (v1.0):** allow customers to tune batch size for their control plane's capacity
- **Delivery guarantees (v1.0):** at-least-once today; exactly-once with idempotency keys in v1.0
- **Encrypted payload at rest on the control plane (v1.0):** customer-supplied KMS key for sensitive captures
