# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Security primitives for AI Runtime Monitor.

Provides five concerns that used to live scattered across monitor.py:
1. Custom CA generation with Name Constraints (only signs AI domains)
2. File permission enforcement (chmod 600/700 on sensitive paths)
3. Dashboard token generation and validation
4. Sensitive-data masking and hashing for alerts
5. Auto-purge of old sensitive data

Everything fails closed: any error returns a safe default rather than
crashing the CLI. The only exception is ``generate_custom_ca`` which
raises if ``cryptography`` is not installed (it's a required dep).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from claude_monitoring.config import get_db_path, get_output_dir

# ─────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────


def get_cert_dir() -> Path:
    return get_output_dir() / "certs"


def get_ca_cert_path() -> Path:
    return get_cert_dir() / "ai-monitor-ca.pem"


def get_ca_key_path() -> Path:
    return get_cert_dir() / "ai-monitor-ca-key.pem"


def get_mitmproxy_confdir() -> Path:
    """Custom mitmproxy confdir that holds our CA in mitmproxy's expected layout."""
    return get_cert_dir() / "mitmproxy"


def get_token_path() -> Path:
    return get_output_dir() / ".dashboard_token"


def get_setup_marker_path() -> Path:
    return get_output_dir() / ".setup_complete"


# ─────────────────────────────────────────────────────────────
# Custom CA generation (Section 2)
# ─────────────────────────────────────────────────────────────


def generate_custom_ca(
    cert_path: Path | None = None,
    key_path: Path | None = None,
    domains: list[str] | None = None,
    hostname: str | None = None,
) -> tuple[Path, Path]:
    """Generate a branded CA cert unique to this install.

    The cert is constrained by X.509 NameConstraints so it can ONLY sign
    leaf certs for the configured AI domains. Even if the CA key is
    compromised, it cannot be used to MITM banking or email — the
    constraint is enforced by the OS cert validator.

    Args:
        cert_path: Where to write the PEM cert. Defaults to the standard path.
        key_path: Where to write the PEM private key (chmod 600).
        domains: DNS names to permit. Defaults to ``AI_PROXY_DOMAINS``.
        hostname: Machine hostname for the CN. Defaults to ``socket.gethostname()``.

    Returns:
        ``(cert_path, key_path)`` — both guaranteed to exist on success.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from claude_monitoring.constants import AI_PROXY_DOMAINS

    cert_path = cert_path or get_ca_cert_path()
    key_path = key_path or get_ca_key_path()
    domains = list(domains) if domains is not None else list(AI_PROXY_DOMAINS)
    hostname = hostname or socket.gethostname()

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(cert_path.parent), 0o700)
    except Exception:
        pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"AI Runtime Monitor - {hostname}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GoCloudForge, Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI Security Monitoring"),
        ]
    )

    permitted = [x509.DNSName(d) for d in domains]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    os.chmod(str(key_path), 0o600)
    os.chmod(str(cert_path), 0o644)  # Cert is public; key is secret.

    # Also write in mitmproxy's expected layout so we can pass --set confdir=...
    mitm_dir = get_mitmproxy_confdir()
    mitm_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(mitm_dir), 0o700)

    # mitmproxy-ca.pem = key + cert in one file
    (mitm_dir / "mitmproxy-ca.pem").write_bytes(key_pem + cert_pem)
    os.chmod(str(mitm_dir / "mitmproxy-ca.pem"), 0o600)

    # mitmproxy-ca-cert.pem = cert only (public)
    (mitm_dir / "mitmproxy-ca-cert.pem").write_bytes(cert_pem)
    os.chmod(str(mitm_dir / "mitmproxy-ca-cert.pem"), 0o644)

    return cert_path, key_path


def get_ca_info(cert_path: Path | None = None) -> dict | None:
    """Return a summary of the installed CA or None if not present."""
    cert_path = cert_path or get_ca_cert_path()
    if not cert_path.exists():
        return None
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        subject_cn = next((a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.3"), "")
        org = next((a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.10"), "")
        try:
            nc_ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
            permitted = [d.value for d in (nc_ext.value.permitted_subtrees or [])]
        except Exception:
            permitted = []
        return {
            "common_name": subject_cn,
            "organization": org,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "permitted_domains": permitted,
            "serial_number": str(cert.serial_number),
        }
    except Exception:
        return None


def trust_ca_cert(cert_path: Path | None = None) -> bool:
    """Prompt for admin password and add the CA to the system keychain.

    Uses osascript for a native macOS password dialog (Touch ID supported)
    rather than a Python subprocess + sudo.
    """
    cert_path = cert_path or get_ca_cert_path()
    if not cert_path.exists():
        return False
    script = (
        f'do shell script "security add-trusted-cert -d -r trustRoot '
        f'-k /Library/Keychains/System.keychain {cert_path}" '
        f"with administrator privileges"
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0
    except Exception:
        return False


def untrust_ca_cert(cert_path: Path | None = None) -> bool:
    cert_path = cert_path or get_ca_cert_path()
    if not cert_path.exists():
        return True
    script = f'do shell script "security remove-trusted-cert -d {cert_path}" with administrator privileges'
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=60)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# File permission enforcement (Section 4a)
# ─────────────────────────────────────────────────────────────

# Paths that must be owner-only readable (chmod 600). Checked on every startup.
_PROTECTED_FILES_600 = [
    lambda: get_db_path(),
    lambda: get_ca_key_path(),
    lambda: get_token_path(),
    lambda: get_setup_marker_path(),
    lambda: get_mitmproxy_confdir() / "mitmproxy-ca.pem",
]

# Directories that must be owner-only traversable (chmod 700).
_PROTECTED_DIRS_700 = [
    lambda: get_output_dir(),
    lambda: get_cert_dir(),
    lambda: get_mitmproxy_confdir(),
]


def enforce_permissions() -> list[str]:
    """Tighten permissions on sensitive paths. Returns list of paths fixed."""
    fixed: list[str] = []

    for resolver in _PROTECTED_DIRS_700:
        try:
            path = resolver()
        except Exception:
            continue
        if not path.exists():
            continue
        try:
            mode = oct(path.stat().st_mode)[-3:]
            if mode != "700":
                os.chmod(str(path), 0o700)
                fixed.append(f"{path.name}/ → 700")
        except Exception:
            pass

    for resolver in _PROTECTED_FILES_600:
        try:
            path = resolver()
        except Exception:
            continue
        if not path.exists():
            continue
        try:
            mode = oct(path.stat().st_mode)[-3:]
            if mode != "600":
                os.chmod(str(path), 0o600)
                fixed.append(f"{path.name} → 600")
        except Exception:
            pass

    return fixed


# ─────────────────────────────────────────────────────────────
# Dashboard token auth (Section 4b)
# ─────────────────────────────────────────────────────────────


def ensure_dashboard_token() -> str:
    """Return the dashboard auth token, creating it if missing.

    Tokens are URL-safe, 32 random bytes (~43 chars after base64). Stored
    with chmod 600 in the output dir so only the running user can read.
    """
    token_path = get_token_path()
    if token_path.exists():
        try:
            tok = token_path.read_text().strip()
            if len(tok) >= 16:
                return tok
        except Exception:
            pass
    token = secrets.token_urlsafe(32)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token)
    try:
        os.chmod(str(token_path), 0o600)
    except Exception:
        pass
    return token


def verify_token(presented: str, expected: str | None = None) -> bool:
    """Constant-time token comparison.

    Uses ``hmac.compare_digest`` so a timing attack can't leak bytes of
    the real token via length of the comparison.
    """
    if not presented:
        return False
    if expected is None:
        try:
            expected = get_token_path().read_text().strip()
        except Exception:
            return False
    if not expected:
        return False
    try:
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Sensitive-data masking (Section 4c)
# ─────────────────────────────────────────────────────────────


def mask_value(value: str | None) -> str:
    """Mask a credential for display: keep first/last 4 chars, star the middle.

    Examples:
        mask_value("AKIAJ5TESTXXXXXXXXXX") -> "AKIA************XXXX"
        mask_value("short")                -> "****"
    """
    if not value:
        return "****"
    if len(value) < 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def hash_value(value: str | None) -> str:
    """Stable 16-char hash of a credential for dedup without storing plaintext."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────
# Sensitive-data auto-purge (Section 4d)
# ─────────────────────────────────────────────────────────────


def purge_old_sensitive_data(db, retention_days: int = 30) -> int:
    """Strip ``snippet`` and ``matched_value`` from old sensitive alerts.

    We keep the alert metadata (pattern, severity, timestamp) forever so the
    dashboard can still show "3 AWS keys leaked in October" — we just remove
    the plaintext fragments after ``retention_days``. Returns the number of
    rows scrubbed.
    """
    try:
        cur = db.execute(
            """UPDATE events
            SET data_json = json_remove(data_json, '$.snippet', '$.matched_value', '$.match_context')
            WHERE event_type = 'sensitive_data'
            AND timestamp < datetime('now', ?)
            AND (
                json_extract(data_json, '$.snippet') IS NOT NULL
                OR json_extract(data_json, '$.matched_value') IS NOT NULL
            )""",
            (f"-{int(retention_days)} days",),
        )
        db.commit()
        return cur.rowcount or 0
    except Exception:
        return 0
