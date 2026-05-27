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
import shlex
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

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

    # x509 CN attribute is capped at 64 chars. "AI Runtime Monitor - " is 22
    # chars, so the hostname gets at most 42. CI runners often have long
    # auto-generated hostnames; truncating is safe — the hostname is cosmetic.
    cn = f"AI Runtime Monitor - {hostname}"[:64]

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
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


def ensure_ca_cert(
    cert_path: Path | None = None,
    key_path: Path | None = None,
    domains: list[str] | None = None,
    min_remaining_days: int = 30,
) -> tuple[Path, Path, bool]:
    """Generate a CA only if a valid one isn't already on disk.

    A cert is "valid" when:
      * the file parses as a PEM x509 certificate
      * ``not_valid_after`` is at least ``min_remaining_days`` in the future
      * the NameConstraints permitted_subtrees match ``domains`` (or
        ``AI_PROXY_DOMAINS`` when ``domains`` is None) — drift means
        AI_PROXY_DOMAINS was updated and the cert needs a refresh

    Returns ``(cert_path, key_path, regenerated)`` where ``regenerated``
    is True if a new cert was written. Idempotent: calling repeatedly
    with the same args returns the same path and ``regenerated=False``.

    Why: Bug 8 — the wizard's prior behavior was unconditional
    regeneration on every ``--setup`` invocation. That created a
    re-run loop: user trusts cert SHA A → ``--setup`` writes cert SHA
    B → verifier correctly reports B is untrusted → user trusts B →
    next ``--setup`` writes C → loop never converges. Idempotent
    generation breaks the loop.
    """
    from cryptography import x509

    from claude_monitoring.constants import AI_PROXY_DOMAINS

    cert_path = cert_path or get_ca_cert_path()
    key_path = key_path or get_ca_key_path()
    expected_domains = list(domains) if domains is not None else list(AI_PROXY_DOMAINS)

    if cert_path.exists() and key_path.exists() and _existing_cert_is_reusable(
        cert_path, expected_domains, min_remaining_days
    ):
        return cert_path, key_path, False
    generate_custom_ca(cert_path=cert_path, key_path=key_path, domains=expected_domains)
    return cert_path, key_path, True


def _existing_cert_is_reusable(cert_path: Path, expected_domains: list[str], min_remaining_days: int) -> bool:
    """Return True iff the cert on disk is parseable, not expiring soon, and has
    NameConstraints whose ``DNSName`` subtrees match ``expected_domains``. Any
    parse failure → False (caller regenerates rather than crashing)."""
    from cryptography import x509
    from cryptography.x509 import DNSName, ExtensionNotFound

    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, OSError):
        return False
    try:
        # not_valid_after_utc can call into key/algorithm accessors that
        # raise cryptography.exceptions.UnsupportedAlgorithm — treat any
        # such failure as a drift signal and regenerate (fail-closed).
        buffer = datetime.now(timezone.utc) + timedelta(days=min_remaining_days)
        if cert.not_valid_after_utc <= buffer:
            return False
    except Exception:
        return False
    try:
        nc_ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
        subtrees = nc_ext.value.permitted_subtrees or []
    except ExtensionNotFound:
        subtrees = []
    # Filter to DNSName-only — any IPAddress / DirectoryName / URI entry
    # is treated as drift so the cert is regenerated. Without this guard,
    # mixed-type subtrees compare IPv4Network() to str and silently
    # mismatch every time → Bug 8 loop under a different root cause.
    dns_entries = [d.value for d in subtrees if isinstance(d, DNSName)]
    if len(dns_entries) != len(subtrees):
        return False
    return set(dns_entries) == set(expected_domains)


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
    # The `do shell script` payload is a POSIX-shell-evaluated string;
    # shlex.quote keeps paths with spaces / shell metacharacters from
    # breaking the invocation. cert_path is config-derived (not user
    # input) so injection isn't the threat — silent misparse of a home
    # directory containing a space is.
    quoted_cert = shlex.quote(str(cert_path))
    script = (
        f'do shell script "security add-trusted-cert -d -r trustRoot '
        f'-k /Library/Keychains/System.keychain {quoted_cert}" '
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


# ─────────────────────────────────────────────────────────────
# Section 2c: CA trust verification (PR #50)
# ─────────────────────────────────────────────────────────────
#
# verify_ca_trusted returns a Literal-typed reason code, not a raw
# string. Callers map the code to a human message via
# trust_reason_message(). Doing the mapping at the call site (with a
# literal-keyed dict) means the data flowing into print/log statements
# is provably from a constrained set, not from a subprocess. CodeQL's
# clear-text-logging taint analysis stops tracking subprocess
# provenance once the return type narrows to a Literal set; the static
# type system proves what taint analysis can't infer.
#
# This is the project convention for surfacing subprocess-derived state
# to users — see CLAUDE.md (will be added in PR 4 / defensive ergonomics).

TrustVerificationCode = Literal[
    "trusted",
    "cert_file_missing",
    "sha1_fingerprint_failed",
    "find_certificate_failed",
    "not_in_keychain",
    "trust_settings_export_failed",
    "in_keychain_but_not_trusted",
    "verification_error",
]


_TRUST_REASON_MESSAGES: dict[TrustVerificationCode, str] = {
    "trusted": "CA is trusted in admin trust settings",
    "cert_file_missing": "CA certificate file is not present on disk — run ai-monitor --setup",
    "sha1_fingerprint_failed": "Could not compute CA certificate SHA-1 fingerprint",
    "find_certificate_failed": "security find-certificate could not be invoked",
    "not_in_keychain": "CA certificate is not present in the System keychain",
    "trust_settings_export_failed": (
        "Could not read the admin trust-settings export — trust may not be applied. Try ai-monitor --setup."
    ),
    "in_keychain_but_not_trusted": (
        "CA is in System.keychain but admin trust settings are not applied. "
        "Run: sudo security add-trusted-cert -d -r trustRoot "
        "-k /Library/Keychains/System.keychain <CA cert path>"
    ),
    "verification_error": "Trust verification error — see logs",
}


def trust_reason_message(code: TrustVerificationCode) -> str:
    """Map a TrustVerificationCode to a human-readable message.

    The dict is keyed by Literal values and contains only hardcoded
    strings, so the returned message is provably from a literal set
    rather than tainted subprocess data. Callers can pass the returned
    string directly to print/log without triggering CodeQL's
    clear-text-logging-sensitive-data alert.
    """
    return _TRUST_REASON_MESSAGES[code]


def _ca_cert_sha1(cert_path: Path) -> str | None:
    """Compute the SHA-1 fingerprint of a PEM-encoded CA cert.

    SHA-1 is the join key macOS uses in both `security find-certificate`
    output (when invoked with -Z) and in trust-settings plists, so a
    fingerprint match is the most reliable way to identify the same cert
    across those two surfaces. SHA-1 is unsafe for forgery but fine as
    an identifier — we're not validating anything cryptographically here.

    Uses ``hashlib.sha1(..., usedforsecurity=False)`` so bandit's B303
    blacklist check recognises the non-security use and does not flag
    it. cryptography's ``hashes.SHA1()`` has no equivalent flag.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_pem_x509_certificate

        cert = load_pem_x509_certificate(cert_path.read_bytes())
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha1(der, usedforsecurity=False).hexdigest()
    except Exception:
        return None


def verify_ca_trusted(cert_path: Path | None = None) -> tuple[bool, TrustVerificationCode]:
    """Return (True, "trusted") iff the CA cert is in System.keychain AND
    has admin trust settings applied. (False, <code>) otherwise.

    The reason channel is a TrustVerificationCode (Literal[str]) drawn
    from a constrained set — never raw subprocess output. Callers map
    the code to a human message via ``trust_reason_message(code)``.
    The discriminated return type breaks CodeQL's taint analysis at
    the function boundary: the literal codes are defined in source, so
    the static type system proves what taint analysis can't infer
    (that the value flowing to print/log is from a literal set).

    A cert can be present in System.keychain without being trusted as a
    root anchor. The two states must be distinguished — only the second
    makes TLS chains validate, which is what proxy interception needs.

    Implementation uses SHA-1 fingerprint as the join key:

      1. ``security find-certificate -Z -a /Library/Keychains/System.keychain``
         emits each cert's SHA-1 (with the -Z flag). If our fingerprint
         appears, the cert is in the keychain.
      2. ``security trust-settings-export -d <plist>`` exports the admin
         trust domain. The plist contains the SHA-1 of every cert with
         explicit trust settings applied. If our fingerprint appears
         there, ``security add-trusted-cert -d`` has been run for it.

    Caller passes ``cert_path`` to override the canonical CA path
    (testing and the cleanup/purge path use this).
    """
    cert_path = cert_path or get_ca_cert_path()
    if not cert_path.exists():
        return False, "cert_file_missing"

    sha1 = _ca_cert_sha1(cert_path)
    if sha1 is None:
        return False, "sha1_fingerprint_failed"
    sha1_upper = sha1.upper()

    # Step 1: keychain presence by SHA-1.
    try:
        find_result = subprocess.run(
            [
                "security",
                "find-certificate",
                "-Z",
                "-a",
                "/Library/Keychains/System.keychain",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except Exception:
        return False, "find_certificate_failed"
    if sha1_upper not in find_result.stdout.upper():
        return False, "not_in_keychain"

    # Step 2: admin trust settings export by SHA-1.
    import tempfile

    plist_path: Path | None = None
    try:
        fd, name = tempfile.mkstemp(suffix=".plist", prefix="ai-monitor-trust-")
        os.close(fd)
        plist_path = Path(name)
        export_result = subprocess.run(
            ["security", "trust-settings-export", "-d", str(plist_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if export_result.returncode != 0:
            # macOS exits non-zero with "no trust settings were found"
            # when the admin trust domain is empty. Map to a Literal
            # code; the stderr is never propagated.
            return False, "trust_settings_export_failed"
        # security trust-settings-export rewrites the file with its own
        # umask (typically 0o644), so the mkstemp 0o600 doesn't survive.
        # Tighten before reading — the plist lists every cert with
        # admin trust + their SHA-1 fingerprints, local-only state
        # that shouldn't be world-readable even briefly.
        try:
            os.chmod(str(plist_path), 0o600)
        except Exception:
            # Best-effort: chmod failure shouldn't block trust verification.
            # The finally clause still deletes the file immediately.
            pass
        plist_bytes = plist_path.read_bytes()
        if sha1_upper not in plist_bytes.decode("utf-8", errors="ignore").upper():
            return False, "in_keychain_but_not_trusted"
        return True, "trusted"
    except Exception:
        return False, "verification_error"
    finally:
        if plist_path is not None:
            plist_path.unlink(missing_ok=True)


def untrust_ca_cert(cert_path: Path | None = None) -> bool:
    cert_path = cert_path or get_ca_cert_path()
    if not cert_path.exists():
        return True
    # See trust_ca_cert: cert_path goes through shlex.quote so paths
    # with spaces don't silently misparse the shell payload.
    quoted_cert = shlex.quote(str(cert_path))
    script = f'do shell script "security remove-trusted-cert -d {quoted_cert}" with administrator privileges'
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
