# Functional Spec — config.py

**Module:** `src/claude_monitoring/config.py`
**Status:** v0.2 launch candidate

## 1. Purpose

`config.py` is the foundation-layer module that owns runtime configuration. Every other module reads configuration through accessor functions exposed here rather than reading TOML files directly. This centralization makes configuration:

- Testable (single point to inject test values)
- Cacheable (one load per process)
- Overridable (CLI flags take priority over file values)
- Discoverable (a single file lists every configurable knob)

The module is dependency-free except for `tomllib` (Python 3.11+) or `tomli` (older versions). It does not import any other project module.

## 2. Configuration sources and priority

Configuration is resolved with this priority order (highest first):

1. **CLI overrides** (via `set_cli_overrides(...)` from `monitor.py::main`)
2. **TOML config file** (first found in the search path)
3. **Built-in defaults** (the `DEFAULTS` dict)

Config file search path:

1. `~/.config/ai-runtime-monitor/config.toml` (XDG-standard preferred location)
2. `~/claude_watch_output/config.toml` (legacy location, retained for backward compatibility)

## 3. Public contract

### 3.1 Loading and override

```python
def load_config(path: str | None = None) -> dict:
    """Load config from TOML file with defaults for missing keys.
    
    If path is provided, only that file is checked. Otherwise the search
    path is used. Returns the merged config dict.
    """

def set_cli_overrides(**kwargs) -> None:
    """Set CLI overrides that take priority over config file values.
    
    Supported kwargs: dashboard_port, proxy_port, bind_address, output_dir.
    """

def reset() -> None:
    """Reset config cache (useful for testing)."""
```

### 3.2 Accessor functions

Every accessor returns a typed value derived from the resolved config:

```python
def get_output_dir() -> Path: ...
def get_db_path() -> Path: ...
def get_session_dir() -> Path: ...
def get_cert_dir() -> Path: ...
def get_dashboard_port() -> int: ...
def get_proxy_port() -> int: ...
def get_bind_address() -> str: ...
def get_cert_path() -> Path: ...
def is_proxy_enabled() -> bool: ...
def get_mcp_known_servers() -> list[str]: ...
def is_mcp_alert_on_unknown() -> bool: ...
```

All return cached values. The cache is populated on first access and invalidated when `set_cli_overrides` or `reset` is called.

### 3.3 Config file generation

```python
def generate_default_config(path: Path | None = None) -> Path:
    """Write a default config.toml with explanatory comments.
    
    Triggered by ai-monitor --init-config. Returns the path written.
    """
```

The generated config is the canonical reference for available knobs. It includes every option with comments explaining what it does.

## 4. Defaults

The `DEFAULTS` dict is the single source of truth for what each config knob defaults to:

```python
DEFAULTS = {
    "server": {
        "dashboard_port": 9081,
        "proxy_port": 9080,
        "bind_address": "127.0.0.1",  # localhost only (security default)
    },
    "paths": {
        "output_dir": str(Path.home() / "claude_watch_output"),
        "db_name": "monitor.db",
        "session_dir": "sessions",
        "cert_dir": "certs",
    },
    "proxy": {
        "enabled": False,  # opt-in
        "auto_configure": False,  # opt-in
        "cert_path": str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"),
    },
    "mcp": {
        "known_servers": [],
        "alert_on_unknown": True,  # alert by default
    },
}
```

Notice that every default that has security implications is set to the safer value:
- Bind address is localhost-only (not 0.0.0.0)
- Proxy is disabled by default (not auto-started)
- Unknown MCP servers trigger alerts (not silenced)

## 5. Inputs

- **TOML files:** parsed via `tomllib.load(file_handle)` (binary mode)
- **CLI overrides:** Python kwargs from `set_cli_overrides`
- **None:** if no config file exists, defaults are used unchanged

## 6. Outputs

- **In-process state:** `_config` cached dict and `_cli_overrides` dict
- **Return values:** typed accessor return values (Path, int, str, bool, list)
- **File:** `generate_default_config` writes a TOML file

## 7. Side effects

- **Module-level state mutation:** `_config` and `_cli_overrides` are module-level globals
- **File system:** `generate_default_config` writes a file (only when called explicitly)

The module-level state is intentional. Configuration is one of the few things where global state is the right pattern; the entire process shares one configuration. The `reset()` function makes this testable.

## 8. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| `tomllib` and `tomli` both unavailable | Defaults are used; no file is loaded | Install Python 3.11+ or `pip install tomli` |
| Config file syntax error | `tomllib.load` raises (uncaught) | Fix the syntax; daemon won't start until then |
| Config file unreadable | Defaults are used (silently) | Fix permissions; rerun |
| Config value has wrong type | Accessor returns the unexpected value | Type checks in callers would catch this; v0.2 has minimal validation |
| `~` expansion fails | Defaults break | Highly unusual; would indicate a corrupted home env |

The v0.2 module is permissive: it favors getting the daemon running over strict validation. v0.3 will add a validation layer that catches type mismatches before the daemon starts.

## 9. Testing

- **Unit tests:** `tests/test_config.py` covers defaults, file loading, CLI override priority, cache invalidation
- **Edge cases:** empty file, missing keys, type mismatches, malformed TOML
- **Idempotency:** loading twice returns the same result

## 10. Extension points

- **Add a new config section:** extend `DEFAULTS` with a new key. Add accessor functions. Document in the generated default config string.
- **Add a new CLI override:** extend the `mapping` dict in `set_cli_overrides`. Wire the corresponding `argparse` argument in `monitor.py::main`.
- **Add validation:** add a `_validate(cfg: dict) -> list[str]` function that returns error messages, call it after loading. Planned v0.3.

## 11. Dependencies

- Standard library: `sys`, `pathlib`
- Third-party (conditional): `tomllib` (3.11+ stdlib) or `tomli` (fallback)

No project module dependencies. This is by design — `config.py` is at the bottom of the dependency graph.

## 12. The XDG question

The XDG Base Directory specification recommends:

- Config in `$XDG_CONFIG_HOME/ai-runtime-monitor/config.toml`
- Data in `$XDG_DATA_HOME/ai-runtime-monitor/`
- Cache in `$XDG_CACHE_HOME/ai-runtime-monitor/`

v0.2 follows XDG for the config file location (`~/.config/...`) but uses `~/claude_watch_output/` for data instead of `~/.local/share/ai-runtime-monitor/`. This is a deliberate compromise:

- Following XDG strictly would require migrating data on upgrade for existing users
- The current location is more visible to users (they can see "what data does this tool keep?")
- v0.3 may add an XDG-strict mode for power users

The legacy `~/claude_watch_output/config.toml` location is retained in the search path so users who customized that file don't lose their customizations.

## 13. Future direction

- **Validation layer (v0.3):** type-check config values; reject unknown keys with a warning
- **Profile support (v0.3):** named profiles for different setups (e.g., `dev`, `production`)
- **Environment variable overrides (v0.3):** `AI_MONITOR_DASHBOARD_PORT=9082`
- **Hot reload (v0.4):** detect config file changes and reload without restart
- **Encrypted config (v1.0 Enterprise):** encrypted at rest for sensitive control plane URLs and tokens
