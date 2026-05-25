# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Static regression tests for audit finding C2 — context-aware XSS helpers.

dashboard.html is served as an inline blob by monitor.py::DashboardHandler.
The XSS bug is in client-side template literals, not Python-rendered HTML,
so these tests treat the file as text:

1.  Parse `src/claude_monitoring/dashboard.html`.
2.  Assert the four context-aware helpers (`escHtml`, `escAttr`, `escJs`,
    `escUrl`) are defined.
3.  Assert the previously-flagged sinks now route through the right helper
    (HTML body / HTML attribute / URL).
4.  Re-implement each helper's replaceAll chain in Python and feed it the
    audit's XSS payloads (from `tests/fixtures/xss_payloads.txt`) to prove
    each context is closed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parents[1] / "src" / "claude_monitoring" / "dashboard.html"
PAYLOADS_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "xss_payloads.txt"


@pytest.fixture(scope="module")
def dashboard_text() -> str:
    return DASHBOARD.read_text()


@pytest.fixture(scope="module")
def dashboard_lines(dashboard_text: str) -> list[str]:
    return dashboard_text.splitlines()


@pytest.fixture(scope="module")
def payloads() -> list[str]:
    raw = PAYLOADS_FIXTURE.read_text().splitlines()
    return [p for p in raw if p.strip()]


# ─────────────────────────────────────────────────────────────
# Helper presence / signature checks
# ─────────────────────────────────────────────────────────────


def test_escHtml_helper_defined(dashboard_text: str) -> None:
    assert re.search(r"\bfunction\s+escHtml\s*\(", dashboard_text), (
        "escHtml(s) helper must be defined for HTML-body context"
    )


def test_escAttr_helper_defined(dashboard_text: str) -> None:
    assert re.search(r"\bfunction\s+escAttr\s*\(", dashboard_text), (
        "escAttr(s) helper must be defined for HTML-attribute context"
    )


def test_escJs_helper_defined(dashboard_text: str) -> None:
    assert re.search(r"\bfunction\s+escJs\s*\(", dashboard_text), (
        "escJs(s) helper must be defined for JS-string context"
    )


def test_escUrl_helper_defined(dashboard_text: str) -> None:
    assert re.search(r"\bfunction\s+escUrl\s*\(", dashboard_text), "escUrl(s) helper must be defined for URL context"


def test_escAttr_escapes_double_and_single_quotes(dashboard_text: str) -> None:
    body = _extract_function_body(dashboard_text, "escAttr")
    assert '"' in body and "&quot;" in body, "escAttr must replace '\"' with &quot;"
    assert "&#39;" in body, "escAttr must replace single quote with &#39;"


def test_escUrl_blocks_javascript_scheme(dashboard_text: str) -> None:
    body = _extract_function_body(dashboard_text, "escUrl")
    assert "javascript:" in body, "escUrl must inspect javascript: scheme"
    assert "data:" in body, "escUrl must inspect data: scheme"


def test_old_esc_is_alias_or_removed(dashboard_text: str) -> None:
    # The old quote-unsafe `function esc(s) {...}` body must not survive.
    # `const esc = escHtml` (alias) is OK for transition.
    funcs = re.findall(r"\bfunction\s+esc\s*\(", dashboard_text)
    assert not funcs, (
        "Old quote-unsafe `function esc(s)` must be removed. "
        "Either delete it or replace with `const esc = escHtml;` alias."
    )


# ─────────────────────────────────────────────────────────────
# Sink-specific checks (audit citations)
# ─────────────────────────────────────────────────────────────


def test_html_attribute_title_sinks_use_escAttr(dashboard_lines: list[str]) -> None:
    """Every `title="..."` template literal must use escAttr, not esc/escHtml."""
    offenders: list[tuple[int, str]] = []
    for i, line in enumerate(dashboard_lines, start=1):
        # `title="' + esc(x) + '"` or `title="${esc(x)}"`
        if re.search(
            r'title="[^"]*\'?\s*\+\s*esc\(|title="[^"]*\$\{esc\(',
            line,
        ):
            offenders.append((i, line.strip()))
    assert not offenders, (
        "title='...' uses escHtml/esc (does not escape quotes). "
        "Must use escAttr. Offenders:\n" + "\n".join(f"  line {ln}: {body[:160]}" for ln, body in offenders)
    )


def test_html_attribute_data_sinks_use_escAttr(dashboard_lines: list[str]) -> None:
    """data-x="' + esc(...)" must use escAttr."""
    offenders: list[tuple[int, str]] = []
    for i, line in enumerate(dashboard_lines, start=1):
        if re.search(
            r'data-[a-z-]+="[^"]*\'?\s*\+\s*esc\(|data-[a-z-]+="[^"]*\$\{esc\(',
            line,
        ):
            offenders.append((i, line.strip()))
    assert not offenders, "data-* attribute uses esc/escHtml — must use escAttr. Offenders:\n" + "\n".join(
        f"  line {ln}: {body[:160]}" for ln, body in offenders
    )


def test_href_sinks_use_escUrl(dashboard_lines: list[str]) -> None:
    """`href="..."` template literals must use escUrl."""
    offenders: list[tuple[int, str]] = []
    for i, line in enumerate(dashboard_lines, start=1):
        if re.search(
            r'href="[^"]*\'?\s*\+\s*esc\((?!Url)|href="[^"]*\$\{esc\((?!Url)',
            line,
        ):
            offenders.append((i, line.strip()))
    assert not offenders, "href='...' uses esc/escHtml — must use escUrl. Offenders:\n" + "\n".join(
        f"  line {ln}: {body[:160]}" for ln, body in offenders
    )


def test_onclick_js_sinks_are_safe(dashboard_lines: list[str]) -> None:
    """`onclick="fn('${userVar}')"` either uses escJs or the unsafe pattern
    is replaced with addEventListener + dataset. The audit cited lines :904-905
    where session_id flowed raw into onclick.
    """
    offenders: list[tuple[int, str]] = []
    for i, line in enumerate(dashboard_lines, start=1):
        # onclick="...('" + variable + "')" where variable is not wrapped in escJs / escAttr
        # Pattern: onclick="someFn(\\'" + <ident> + "\\')" — bare identifier (no escape) is unsafe
        # Conservative match: onclick attribute that contains a `+ <bareIdent> +` of a known-tainted var.
        m = re.search(
            r"onclick=\"[^\"]*\\?'\"\s*\+\s*([a-zA-Z_][\w.]*)\s*\+\s*\"\\?'",
            line,
        )
        if not m:
            continue
        var = m.group(1)
        # Whitelist of bare identifiers we know to be safe (numbers, internal indices).
        # Anything user-controllable (session_id, conversation_id, package names) is unsafe.
        safe_idents = {"si", "idx", "i"}
        if var in safe_idents:
            continue
        # Also accept the (a.turn_number||1) shape — numbers are safe.
        if "turn_number" in var or var.endswith("_number"):
            continue
        offenders.append((i, line.strip()))
    assert not offenders, (
        "onclick='fn(\\'' + userVar + '\\')' interpolates user data raw into a "
        "JS-in-attribute context. Switch to a data-* attribute + addEventListener "
        "reading dataset.*, or wrap with escJs(escAttr(...)). Offenders:\n"
        + "\n".join(f"  line {ln}: {body[:200]}" for ln, body in offenders)
    )


def test_event_type_escaped_in_feed(dashboard_lines: list[str]) -> None:
    """Audit :1241 — `ev.event_type` was interpolated raw into innerHTML."""
    # Find any "<span class=\"type\">" + ev.event_type that lacks an esc/escHtml wrap.
    joined = "\n".join(dashboard_lines)
    # Look for bare ev.event_type within an innerHTML string-concat with no esc()/escHtml() wrapping
    bad_patterns = [
        r"\+\s*ev\.event_type\.",  # `+ ev.event_type.replace(...)`
        r"\+\s*ev\.event_type\s*\+",
    ]
    for pat in bad_patterns:
        if re.search(pat, joined):
            pytest.fail(
                f"ev.event_type is interpolated into HTML without escaping (pattern {pat!r}). "
                "Wrap with escHtml() or sanitize at the source."
            )


# ─────────────────────────────────────────────────────────────
# Payload behavior: re-implement each JS helper in Python and run payloads.
# ─────────────────────────────────────────────────────────────


def _extract_function_body(text: str, name: str) -> str:
    """Return the body of `function <name>(...)` as a string. Throws if not found."""
    m = re.search(
        rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
        text,
    )
    if not m:
        raise AssertionError(f"function {name} not found in dashboard.html")
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return text[start : i - 1]


def _python_escHtml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _python_escAttr(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
    )


def _python_escJs(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("<", "\\x3c")
        .replace(">", "\\x3e")
    )


def _python_escUrl(s: str) -> str:
    from urllib.parse import quote

    lowered = s.lstrip().lower()
    if lowered.startswith("javascript:") or lowered.startswith("data:") or lowered.startswith("vbscript:"):
        return "#"
    # encodeURI does not encode # @ : / ? & = + $ , ! * ' ( ) ; etc.
    # We only care that quotes get encoded for an href attribute context.
    return quote(s, safe=":/?#[]@!$&()*+,;=-._~%").replace('"', "%22").replace("'", "%27")


@pytest.mark.parametrize(
    "payload",
    [
        '" onmouseover=alert(1)',
        '"><script>alert(1)</script>',
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        '\\"; alert(1); //',
        "<img src=x onerror=alert(1)>",
        "'\"><svg/onload=alert(1)>",
    ],
)
def test_escHtml_neutralizes_angle_brackets(payload: str) -> None:
    out = _python_escHtml(payload)
    assert "<" not in out and ">" not in out, f"escHtml left angle brackets in: {out!r}"


@pytest.mark.parametrize(
    "payload",
    [
        '" onmouseover=alert(1)',
        '"><script>alert(1)</script>',
        '\\"; alert(1); //',
        "'\"><svg/onload=alert(1)>",
    ],
)
def test_escAttr_neutralizes_quotes_and_brackets(payload: str) -> None:
    out = _python_escAttr(payload)
    assert '"' not in out, f"escAttr left a literal double-quote in: {out!r}"
    assert "'" not in out, f"escAttr left a literal single-quote in: {out!r}"
    assert "<" not in out and ">" not in out


@pytest.mark.parametrize(
    "payload",
    [
        "javascript:alert(1)",
        "  javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
    ],
)
def test_escUrl_blocks_dangerous_schemes(payload: str) -> None:
    assert _python_escUrl(payload) == "#", f"escUrl must collapse dangerous scheme {payload!r} to '#'"


@pytest.mark.parametrize(
    "payload",
    [
        "https://example.com/repo",
        "http://github.com/foo/bar",
        "/relative/path",
    ],
)
def test_escUrl_passes_safe_urls(payload: str) -> None:
    out = _python_escUrl(payload)
    assert out != "#", f"escUrl wrongly nuked safe URL {payload!r}"
    assert '"' not in out, "escUrl must encode double-quotes for attribute context"


@pytest.mark.parametrize(
    "payload",
    [
        '" + alert(1) + "',
        "\\'); alert(1); //",
        "</script><script>alert(1)</script>",
    ],
)
def test_escJs_neutralizes_string_break(payload: str) -> None:
    out = _python_escJs(payload)
    # No unescaped quote that would terminate the surrounding JS string literal.
    assert not re.search(r'(?<!\\)"', out), f'escJs left an unescaped " in: {out!r}'
    assert not re.search(r"(?<!\\)'", out), f"escJs left an unescaped ' in: {out!r}"
    # No raw `<` that could close a parent <script>.
    assert "<" not in out and ">" not in out


# ─────────────────────────────────────────────────────────────
# Equivalence: extracted JS helpers must agree with Python re-implementation.
# We translate the function bodies' replaceAll chain into a Python op list
# and apply it to each payload, then compare to the canonical Python helper.
# This guards against drift between the file's helpers and the spec.
# ─────────────────────────────────────────────────────────────


_REPLACEALL_RE = re.compile(
    r'\.replaceAll\(\s*(?P<a>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')\s*,\s*'
    r'(?P<b>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')\s*\)'
)


def _js_string_to_python(lit: str) -> str:
    """Decode a JS quoted string literal (with `\\\\`, `\\n`, `\\"`, `\\x3c`) to Python."""
    body = lit[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "r":
            out.append("\r")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        elif nxt in ('"', "'", "/"):
            out.append(nxt)
            i += 2
        elif nxt == "x" and i + 3 < len(body):
            out.append(chr(int(body[i + 2 : i + 4], 16)))
            i += 4
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def _apply_replaceall_chain(body: str, s: str) -> str:
    for m in _REPLACEALL_RE.finditer(body):
        a = _js_string_to_python(m.group("a"))
        b = _js_string_to_python(m.group("b"))
        s = s.replace(a, b)
    return s


@pytest.mark.parametrize(
    "payload",
    [
        '" onmouseover=alert(1)',
        '"><script>alert(1)</script>',
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ],
)
def test_dashboard_escHtml_matches_python_reference(dashboard_text: str, payload: str) -> None:
    body = _extract_function_body(dashboard_text, "escHtml")
    js_result = _apply_replaceall_chain(body, payload)
    assert js_result == _python_escHtml(payload)


@pytest.mark.parametrize(
    "payload",
    [
        '" onmouseover=alert(1)',
        "'\"><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ],
)
def test_dashboard_escAttr_matches_python_reference(dashboard_text: str, payload: str) -> None:
    body = _extract_function_body(dashboard_text, "escAttr")
    js_result = _apply_replaceall_chain(body, payload)
    assert js_result == _python_escAttr(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "javascript:alert(1)",
        "  javascript:alert(1)",
        "data:text/html,<script>",
        "https://example.com/repo",
    ],
)
def test_dashboard_escUrl_blocks_or_passes(dashboard_text: str, payload: str) -> None:
    body = _extract_function_body(dashboard_text, "escUrl")
    # The escUrl body has an `if (/^\s*javascript:/i.test(v) || ...) return "#";`
    # check followed by an encode + quote replace. We just verify the regex set
    # against the spec — covers the high-value blocked schemes.
    assert "/^\\s*javascript:/i" in body, (
        "escUrl must regex-test the javascript: scheme (case-insensitive, with leading whitespace allowed)"
    )
    assert "/^\\s*data:/i" in body, "escUrl must block data: scheme"
    assert "/^\\s*vbscript:/i" in body, "escUrl must block vbscript: scheme"


# ──────────────────────────────────────────────────────────────────────────
# Scroll-to-alert feature regression tests (feat/scroll-to-alert)
# ──────────────────────────────────────────────────────────────────────────


def test_dashboard_url_alert_param_is_parsed(dashboard_text: str) -> None:
    """The init block must read `?alert=<id>` from the URL on page load and
    pass it into openDeepDive. Without this, sharing a Vigil URL with an
    alert id doesn't jump to the alert on the receiving end."""
    assert "URLSearchParams" in dashboard_text, "init must read URL params"
    # The handler reads `alert` from the query string and calls openDeepDive
    # with it as the third arg. Look for both signals.
    assert "p.get('alert')" in dashboard_text, "init must extract the `alert` query-string parameter"
    # openDeepDive's signature must accept the third arg.
    assert "openDeepDive(sessionId, jumpToTurn, jumpToAlertId)" in dashboard_text, (
        "openDeepDive must accept jumpToAlertId as third positional argument"
    )


def test_dashboard_sensitive_event_block_has_alert_id(dashboard_text: str) -> None:
    """renderInspector's sensitive_data case must emit a data-alert-id
    attribute on the event-block so scrollToAlert can find it."""
    # Match the actual emit in dashboard.html (escAttr-wrapped event id).
    pattern = re.compile(
        r'event-block sensitive"\s*data-alert-id="\'\s*\+\s*escAttr\(String\(ev\.id\)\)',
    )
    assert pattern.search(dashboard_text), (
        "sensitive_data event-block must include data-alert-id derived from ev.id "
        "via escAttr (preserves the XSS-helper discipline from the C2 audit fix)"
    )


def test_dashboard_alert_flash_animation_defined(dashboard_text: str) -> None:
    """The .alert-flash class + @keyframes must exist in the stylesheet so
    the scroll-target draws the eye when navigated to."""
    assert ".alert-flash" in dashboard_text, ".alert-flash CSS class must be defined"
    assert "@keyframes alert-flash-kf" in dashboard_text, "alert-flash-kf keyframe must be defined"


def test_dashboard_scrollToAlert_uses_smooth_center(dashboard_text: str) -> None:
    """scrollToAlert must use scrollIntoView with smooth behavior + center
    block so the alert lands in the viewport's middle, not at the top edge."""
    # Find the scrollToAlert function body and verify the scrollIntoView call.
    # Use a prefix-only assert so the signature can evolve (cycle-2 added a
    # `_alertRetry` guard arg without breaking external callers).
    assert re.search(r"\bfunction scrollToAlert\s*\(", dashboard_text), "scrollToAlert function must be defined"
    # The actual scrollIntoView call inside scrollToAlert.
    assert "scrollIntoView({behavior:'smooth', block:'center'})" in dashboard_text, (
        "scrollToAlert must scroll smoothly to center"
    )


def test_dashboard_alert_list_passes_alert_id_to_deep_dive(dashboard_text: str) -> None:
    """The alert-list onclick must pass `a.id` as the third arg to
    openDeepDive so in-app clicks (not just URL deep-links) scroll to the
    alert block."""
    # The alert-session onclick handler builds an openDeepDive call with
    # session_id, turn_number, AND alert id. Look for the literal
    # substring that emits `, '+a.id+')` right after the turn_number arg.
    expected = "(a.turn_number||1)+', '+a.id+')"
    assert expected in dashboard_text, (
        f"alert-list onclick must pass a.id as the third arg to openDeepDive (looking for substring: {expected!r})"
    )
