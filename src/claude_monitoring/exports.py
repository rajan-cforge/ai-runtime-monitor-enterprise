"""P5.2 — Attack-Surface asset inventory exports (JSON / CSV / Markdown).

Spec §2.5 item 2 (verbatim, `v022-attack-surface-feature-spec-v1-LOCKED.md:173`):

    2. Export formats serve security team workflows:
       - JSON export (mandatory for v0.2.2 core)
       - CSV export of asset list (mandatory)
       - Markdown report (mandatory)
       - PDF report (deferred to v0.2.3 if heavy lift)
       - SARIF format for SIEM ingestion (deferred to v0.2.3)

Directive line 207 anchors P5.2 to spec §2.5 as a C2 PR. Directive
acceptance line 1774: "All export formats (JSON/CSV/Markdown) produce
valid output."

Load-bearing contract (judge p5.2.a1 APPROVE 2026-06-15):

    Every cell that ends up in an export file routes through
    `privacy_audit.redact_value_for_display("assets", column, value)`
    UNCONDITIONALLY. The redaction primitive shipped in P5.1b (#128,
    security-C4 human-reviewed) is the single source of truth for what
    a cell's display string is. P5.2 must not re-derive a second
    redaction path — exports inherit the audit's masking semantics.

Capture tables (CAPTURE_TABLES_NO_SAMPLES from privacy_audit) are NOT
exported in v0.2.2. Only the attack-surface `assets` table is. The
collector's contract enforces this — it ONLY queries `assets` — and the
primitive raises ValueError if accidentally invoked on a capture table.

The CSV / dict-row column vocabulary is the
`SAFE_COLUMNS_BY_TABLE["assets"]` key set. P5.4 (SECURITY-MAPPING.md)
aligns its standards-mapping doc to this same set (per the P5.2 → P5.4
carry-forward captured in the Phase A submission).
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
import json
import sqlite3
from collections.abc import Iterable

from claude_monitoring.privacy_audit import (
    CAPTURE_TABLES_NO_SAMPLES,
    SAFE_COLUMNS_BY_TABLE,
    redact_value_for_display,
)

# Authoritative column vocabulary for v0.2.2 exports. Pinned to the
# assets-table classification from P5.1b so every column has a defined
# display policy. P5.4 aligns SECURITY-MAPPING.md to this same set.
_EXPORT_COLUMNS: tuple[str, ...] = tuple(SAFE_COLUMNS_BY_TABLE["assets"].keys())


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def collect_assets_for_export(conn: sqlite3.Connection) -> list[dict[str, str]]:
    """Walk the `assets` table and return a list of display-ready dicts.

    Every cell is routed through ``redact_value_for_display`` so the
    returned rows are safe to write to disk / stdout verbatim.

    The collector queries ONLY the `assets` table. Capture tables
    (`api_calls`, `events`, ...) are not touched; the
    `CAPTURE_TABLES_NO_SAMPLES` policy that P5.1b enforces for
    `--db-audit` is preserved here by construction.
    """
    # Defensive: the `assets` table must NOT be in the capture-tables set
    # (an invariant violation here would indicate a misclassification).
    if "assets" in CAPTURE_TABLES_NO_SAMPLES:
        raise RuntimeError(
            "exports.collect_assets_for_export: invariant breach — "
            "'assets' is classified as a capture table; refusing to read."
        )

    # Build a fixed-order column list bound by `_EXPORT_COLUMNS`.
    # Bandit B608: the column list comes from `_EXPORT_COLUMNS`, a
    # module-level literal derived from SAFE_COLUMNS_BY_TABLE — never
    # from user input. The table name is the literal "assets".
    select_cols = ", ".join(_EXPORT_COLUMNS)
    sql = f"SELECT {select_cols} FROM assets"  # nosec B608
    rows: list[dict[str, str]] = []
    for raw in conn.execute(sql).fetchall():
        row: dict[str, str] = {}
        for col_name, raw_value in zip(_EXPORT_COLUMNS, raw, strict=False):
            row[col_name] = redact_value_for_display("assets", col_name, raw_value)
        rows.append(row)
    return rows


def render_json(rows: list[dict[str, str]]) -> str:
    """Pretty-printed JSON. Envelope = ``{generated_at, asset_count, assets}``."""
    envelope = {
        "generated_at": _utc_now_iso(),
        "asset_count": len(rows),
        "assets": rows,
    }
    return json.dumps(envelope, indent=2, sort_keys=False) + "\n"


def render_csv(rows: list[dict[str, str]]) -> str:
    """RFC-4180 CSV with header row matching ``_EXPORT_COLUMNS``."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(_EXPORT_COLUMNS),
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def render_markdown(rows: list[dict[str, str]]) -> str:
    """CISO-handoff Markdown — summary block, per-source breakdown, then a
    table of every asset. Reads top-to-bottom: what's installed, where it
    came from, then the inventory itself."""
    generated = _utc_now_iso()
    asset_count = len(rows)

    # Summary by risk band.
    band_counts: dict[str, int] = {}
    for r in rows:
        band = r.get("risk_band") or "—"
        band_counts[band] = band_counts.get(band, 0) + 1

    # Per-source breakdown.
    source_counts: dict[str, int] = {}
    for r in rows:
        src = r.get("source") or "—"
        source_counts[src] = source_counts.get(src, 0) + 1

    out: list[str] = []
    out.append("# Vigil Attack-Surface Inventory Export\n")
    out.append(f"Generated: `{generated}`  ")
    out.append(f"Total assets: **{asset_count}**\n")
    out.append("## Summary by risk band\n")
    if band_counts:
        out.append("| Band | Count |")
        out.append("|---|---|")
        for band, count in sorted(band_counts.items()):
            out.append(f"| {band} | {count} |")
    else:
        out.append("_No assets discovered._")
    out.append("")
    out.append("## Per-source breakdown\n")
    if source_counts:
        out.append("| Source | Asset count |")
        out.append("|---|---|")
        for src, count in sorted(source_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            out.append(f"| {src} | {count} |")
    else:
        out.append("_No sources represented._")
    out.append("")
    out.append("## Asset inventory\n")
    if rows:
        out.append("| " + " | ".join(_EXPORT_COLUMNS) + " |")
        out.append("|" + "|".join(["---"] * len(_EXPORT_COLUMNS)) + "|")
        for row in rows:
            cells = [_md_escape(row.get(col, "")) for col in _EXPORT_COLUMNS]
            out.append("| " + " | ".join(cells) + " |")
    else:
        out.append("_No assets in inventory._")
    out.append("")
    out.append("---")
    out.append(
        "All cells routed through `privacy_audit.redact_value_for_display` "
        "(P5.1b). Capture-table content is excluded from this export per "
        "the `CAPTURE_TABLES_NO_SAMPLES` policy."
    )
    return "\n".join(out) + "\n"


def _md_escape(value: object) -> str:
    """Escape `|` and newlines so a single cell can't break the table row."""
    s = "" if value is None else str(value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", "")


_FORMATS = {
    "json": render_json,
    "csv": render_csv,
    "md": render_markdown,
}


def export_assets(fmt: str, conn: sqlite3.Connection) -> str:
    """Top-level entry — collect + render one of the three formats."""
    if fmt not in _FORMATS:
        raise ValueError(f"unknown export format {fmt!r}; want one of {sorted(_FORMATS)}")
    rows = collect_assets_for_export(conn)
    return _FORMATS[fmt](rows)


def supported_formats() -> Iterable[str]:
    """Set of supported `--export` argument values."""
    return tuple(_FORMATS)


def export_assets_to_destination(fmt: str, output_path: str | None) -> int:
    """CLI entry: open the live DB, render, write to ``output_path`` (or
    stdout when None). Returns process exit code.

    Atomic write: render to a tempfile in the same directory, then
    rename — so a partial / failed render never overwrites a previous
    good export with a half-written file.
    """
    import sys
    import tempfile
    from pathlib import Path

    from claude_monitoring.db import get_db_path

    db_path = get_db_path()
    if not Path(db_path).exists():
        print(f"export: monitor.db not found at {db_path}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(db_path)
    try:
        rendered = export_assets(fmt, conn)
    finally:
        conn.close()

    if output_path is None:
        print(rendered, end="")
        return 0

    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write — render to a sibling tempfile, then rename.
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=out.parent,
        prefix=out.name + ".",
        suffix=".tmp",
        delete=False,
    ) as tf:
        tf.write(rendered)
        tmp_path = Path(tf.name)
    tmp_path.replace(out)
    print(f"export: wrote {len(rendered.encode('utf-8'))} bytes to {out}", file=sys.stderr)
    return 0
