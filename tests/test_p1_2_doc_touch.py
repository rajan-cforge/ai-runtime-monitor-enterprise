"""Doc-touch tests for P1.2.

Per Rajan's 2026-06-05 Phase B review: assertions go beyond pure
presence to check load-bearing strings. A heading can exist while
saying the wrong thing — these tests stop the docs from drifting away
from the ratified security decisions.

NOT full content diffs (those rot).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSpecDocsPinRatifiedDecisions:
    def test_discovery_source_doc_has_per_item_isolation_core_rule(self) -> None:
        """`docs/spec/DISCOVERY-SOURCE.md` contains §10 "Per-item isolation"
        AND its core rule sentence. Stricter than heading-presence."""
        doc = (REPO_ROOT / "docs" / "spec" / "DISCOVERY-SOURCE.md").read_text()
        assert "## 10. Per-item isolation" in doc, "§10 heading missing — drifted"
        # Core rule sentence — pins the cross-cutting contract
        assert "wrap per-item work in `try/except`" in doc, "§10 core rule sentence missing — drifted"
        assert "MUST NOT zero out" in doc, "§10 invariant phrase missing — drifted"

    def test_threat_model_doc_has_b6_partially_mitigated(self) -> None:
        """`docs/spec/THREAT-MODEL.md` contains the Vigil Discovery boundary
        section AND the literal phrase 'PARTIALLY mitigated'. Pins the
        not-closed status per Q1 ratification.

        Originally labelled B7; renumbered to B6 by the
        control-plane-feature-removal PR (B3 Daemon↔Control Plane was
        deleted; B4-B7 became B3-B6)."""
        doc = (REPO_ROOT / "docs" / "spec" / "THREAT-MODEL.md").read_text()
        assert "B6" in doc, "B6 boundary not present — drifted"
        assert "Vigil Discovery" in doc, "Vigil Discovery boundary name missing — drifted"
        assert "PARTIALLY mitigated" in doc, "Status MUST be 'PARTIALLY mitigated' per Q1"

    def test_data_classification_doc_has_attack_surface_tier_words(self) -> None:
        """`docs/spec/DATA-CLASSIFICATION.md` contains tier words (Critical AND
        Internal) for the three attack-surface data types. Pins the Q2 ratified
        classification.

        Heading + tier-word adjacency check — not a content diff (those rot)."""
        doc = (REPO_ROOT / "docs" / "spec" / "DATA-CLASSIFICATION.md").read_text()
        assert "Attack-surface data" in doc, "attack-surface section missing — drifted"
        # The three data types must each appear with tier words near them.
        # Use a structural check: find the section, ensure tier words are present.
        section_start = doc.find("Attack-surface data")
        assert section_start != -1
        section_end = doc.find("## 3. Data flow", section_start)
        assert section_end != -1
        section = doc[section_start:section_end]
        assert "Critical" in section, "pre-redaction config bytes MUST be Critical tier"
        assert "Internal" in section, "post-redaction current_state MUST be Internal tier"
        assert "chmod-600" in section, "chmod-600 backstop framing required per Q2 + ADD-2"
        assert "current_state" in section, "Asset.current_state data type missing"
        assert "assets`" in section or "assets table" in section.lower(), "assets table row missing"
