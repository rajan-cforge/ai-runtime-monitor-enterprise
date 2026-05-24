"""Project-wide Protocols for interface contracts.

Each Protocol defines a structural contract that implementing classes
must satisfy. Conformance is enforced by tests under
``tests/architecture/``.

Adding a new Protocol:
  1. Define it in its own module under this package.
  2. Re-export it from ``__all__`` below.
  3. Create ``tests/architecture/test_<name>_conformance.py``.
     The ``test_protocol_inventory`` meta-test will fail if you skip
     this step.
"""

from claude_monitoring.protocols.scanner import Finding, Scanner, ScannerHealth

__all__ = ["Finding", "Scanner", "ScannerHealth"]
