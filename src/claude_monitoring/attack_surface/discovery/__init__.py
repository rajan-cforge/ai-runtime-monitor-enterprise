"""Discovery layer for v0.2.2 attack surface.

P1.1 lands the foundation: :class:`DiscoverySource` base class +
``run_with_safety`` orchestration entry point + thread-safe timeout
helper. P1.2 adds the safe input-handling helpers consumed by every
concrete source (Phases 1.4 onward).

Public surface (P1.1 + P1.2):

- :class:`~claude_monitoring.attack_surface.discovery.base.DiscoverySource`
- :func:`~claude_monitoring.attack_surface.discovery.helpers.safe_yaml_load`
- :func:`~claude_monitoring.attack_surface.discovery.helpers.safe_subprocess`
- :func:`~claude_monitoring.attack_surface.discovery.helpers.validate_path`
- :func:`~claude_monitoring.attack_surface.discovery.helpers.redact_secrets_in_env`
"""

from __future__ import annotations

from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import (
    redact_secrets_in_env,
    safe_subprocess,
    safe_yaml_load,
    validate_path,
)

__all__ = [
    "DiscoverySource",
    "redact_secrets_in_env",
    "safe_subprocess",
    "safe_yaml_load",
    "validate_path",
]
