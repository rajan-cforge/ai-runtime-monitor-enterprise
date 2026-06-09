"""Homebrew AI tools discovery — P3.6.

Invokes ``brew info --json=v2 --installed`` against the system Homebrew
and filters the result for AI-related formulae and casks via a
keyword match against ``name`` + ``full_name`` + ``desc``.

(NOTE on directive wording: the directive says ``brew list --json=v2``
but ``brew list`` does not accept ``--json=v2`` — verified empirically.
``brew info --json=v2 --installed`` is the correct invocation. Documented
inline so reviewers don't get confused.)

**Locked refs:**

- directive §3 P3.6 — "Homebrew AI tools discovery. ``brew list --json=v2``,
  filter for AI-related formulas." (See note above re: command spelling.)
- memory ``project_v022_per_item_isolation.md`` — per-item try/except
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``,
  NOT Python's built-in ``hash()``

**Source name:** ``"homebrew-ai-tools"``.

**Asset.id digest input:**
``sha256(item_type|name_normalized|cellar_path)``.
``version`` is EXCLUDED so upgrades UPSERT.
``name_normalized`` is lowercase (brew is case-insensitive).

**Binary-trust boundary (mirrors P3.3 / P3.5):** brew candidate
generation restricted to ratified prefixes (``/opt/homebrew/``,
``/usr/local/``, ``Path.home()``).

**Redaction:** NOT performed. ``brew info`` output is public catalog
metadata. No user secrets.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import brew_info_json

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.homebrew_ai_tools")


SOURCE_NAME = "homebrew-ai-tools"

DESCRIPTION_TRUNCATE = 500

AI_KEYWORDS: frozenset[str] = frozenset(
    {
        # Local LLM runners
        "ollama",
        "llama",
        "llama-cpp",
        "llamaindex",
        # Model hubs / orchestration
        "huggingface",
        "transformers",
        "langchain",
        "llm",
        # ML frameworks
        "pytorch",
        "tensorflow",
        "jax",
        "mlx",
        "onnx",
        "onnxruntime",
        "openvino",
        # Inference / serving
        "vllm",
        "gguf",
        # NLP / specific
        "spacy",
        "nltk",
        "whisper",
        # GPT / OpenAI / Anthropic family
        "gpt",
        "gpt4all",
        "gpt-engineer",
        "anthropic",
        "openai",
        # GPU runtimes
        "cuda",
        "cudnn",
        "rocm",
    }
)
"""Conservative AI-keyword list. Bias toward false positives over false
negatives; P3.8 can refine. Match is case-insensitive substring."""


_RATIFIED_BREW_PREFIXES = (
    Path("/opt/homebrew"),
    Path("/usr/local"),
    Path.home(),
)


def _is_under_ratified_prefix(candidate: Path) -> bool:
    try:
        resolved = candidate.resolve()
    except OSError:
        return False
    for prefix in _RATIFIED_BREW_PREFIXES:
        try:
            resolved.relative_to(prefix)
            return True
        except ValueError:
            continue
    return False


def _default_brew_candidates() -> list[Path]:
    """Production defaults: well-known brew install locations under
    ratified prefixes."""
    candidates: list[Path] = []
    for static_path in (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew")):
        if static_path.exists():
            candidates.append(static_path)
    which_result = shutil.which("brew")
    if which_result:
        which_path = Path(which_result)
        if _is_under_ratified_prefix(which_path) and which_path not in candidates:
            candidates.append(which_path)
    return candidates


def _match_ai_keyword(
    *,
    name: str,
    full_name: str,
    desc: str | None,
    keywords: frozenset[str],
) -> dict | None:
    """Return ``{"keyword": ..., "field": ...}`` for the first keyword
    that matches any of (name, full_name, desc), case-insensitive
    substring. Returns ``None`` when no keyword matches."""
    name_l = name.lower()
    full_l = full_name.lower()
    desc_l = (desc or "").lower()
    for kw in keywords:
        if kw in name_l:
            return {"keyword": kw, "field": "name"}
        if kw in full_l:
            return {"keyword": kw, "field": "full_name"}
        if desc_l and kw in desc_l:
            return {"keyword": kw, "field": "desc"}
    return None


class HomebrewAiToolsSource(DiscoverySource):
    """Discovers AI-related Homebrew formulae and casks."""

    def __init__(
        self,
        brew_candidates: list[Path] | None = None,
        ai_keywords: frozenset[str] | None = None,
    ) -> None:
        """Args:
        brew_candidates: Optional override list of brew binary paths.
            Default scans ratified prefixes.
        ai_keywords: Optional override keyword set. Tests inject narrow
            sets for assertion stability.
        """
        self._brew_candidates = brew_candidates if brew_candidates is not None else _default_brew_candidates()
        self._ai_keywords = ai_keywords if ai_keywords is not None else AI_KEYWORDS

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Subprocess invocation; no authentication required."""
        return False

    def discover(self) -> list[Asset]:
        """Invoke `brew info --json=v2 --installed` against the first
        existing brew candidate; filter to AI-related items.

        Per-item isolation at TWO layers:
        1. Per-source-path: subprocess failure → log + skip; source returns [].
        2. Per-item: one malformed formula / cask skipped; siblings emit.
        """
        for brew_bin in self._brew_candidates:
            try:
                if not brew_bin.exists():
                    continue
            except OSError:
                continue
            try:
                data = brew_info_json(brew_bin)
            except Exception as exc:
                logger.warning(
                    "homebrew-ai-tools: brew_info_json failed (%s) — %s",
                    brew_bin,
                    exc,
                )
                return []
            return self._filter_and_emit(data)
        return []

    def _filter_and_emit(self, data: dict) -> list[Asset]:
        out: list[Asset] = []
        formulae = data.get("formulae")
        if isinstance(formulae, list):
            for entry in formulae:
                try:
                    asset = self._maybe_formula_asset(entry)
                except Exception as exc:
                    logger.warning("homebrew-ai-tools: skipping formula — %s", exc)
                    continue
                if asset is not None:
                    out.append(asset)
        casks = data.get("casks")
        if isinstance(casks, list):
            for entry in casks:
                try:
                    asset = self._maybe_cask_asset(entry)
                except Exception as exc:
                    logger.warning("homebrew-ai-tools: skipping cask — %s", exc)
                    continue
                if asset is not None:
                    out.append(asset)
        return out

    def _maybe_formula_asset(self, entry: object) -> Asset | None:
        if not isinstance(entry, dict):
            return None
        name = entry.get("name")
        if not isinstance(name, str):
            return None
        full_name = entry.get("full_name") if isinstance(entry.get("full_name"), str) else name
        desc = entry.get("desc") if isinstance(entry.get("desc"), str) else None
        match = _match_ai_keyword(
            name=name,
            full_name=full_name,
            desc=desc,
            keywords=self._ai_keywords,
        )
        if match is None:
            return None
        # version + cellar from installed[]; fall back to versions.stable
        installed = entry.get("installed")
        version: str | None = None
        cellar: str | None = None
        if isinstance(installed, list) and installed:
            first = installed[0]
            if isinstance(first, dict):
                v = first.get("version")
                version = v if isinstance(v, str) else None
                c = first.get("cellar")
                cellar = c if isinstance(c, str) else None
        if version is None:
            versions = entry.get("versions")
            if isinstance(versions, dict):
                v = versions.get("stable")
                version = v if isinstance(v, str) else None
        if cellar is None:
            cellar = f"/opt/homebrew/Cellar/{name}"
        return self._make_asset(
            item_type="formula",
            name=name,
            full_name=full_name,
            version=version,
            cellar_path=cellar,
            desc=desc,
            homepage=entry.get("homepage") if isinstance(entry.get("homepage"), str) else None,
            tap=entry.get("tap") if isinstance(entry.get("tap"), str) else None,
            deprecated=bool(entry.get("deprecated")),
            dependencies=entry.get("dependencies") if isinstance(entry.get("dependencies"), list) else None,
            match_reason=match,
        )

    def _maybe_cask_asset(self, entry: object) -> Asset | None:
        if not isinstance(entry, dict):
            return None
        token = entry.get("token")
        if not isinstance(token, str):
            return None
        desc = entry.get("desc") if isinstance(entry.get("desc"), str) else None
        match = _match_ai_keyword(
            name=token,
            full_name=token,
            desc=desc,
            keywords=self._ai_keywords,
        )
        if match is None:
            return None
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        cellar = f"/opt/homebrew/Caskroom/{token}"
        return self._make_asset(
            item_type="cask",
            name=token,
            full_name=token,
            version=version,
            cellar_path=cellar,
            desc=desc,
            homepage=entry.get("homepage") if isinstance(entry.get("homepage"), str) else None,
            tap=entry.get("tap") if isinstance(entry.get("tap"), str) else None,
            deprecated=bool(entry.get("deprecated")),
            dependencies=None,
            match_reason=match,
        )

    @staticmethod
    def _make_asset(
        *,
        item_type: str,
        name: str,
        full_name: str,
        version: str | None,
        cellar_path: str,
        desc: str | None,
        homepage: str | None,
        tap: str | None,
        deprecated: bool,
        dependencies: list | None,
        match_reason: dict,
    ) -> Asset:
        name_normalized = name.lower()
        # Defensive: lowercase the cellar path component of the digest so a
        # case variation of the formula name (which brew normalizes in
        # practice but isn't guaranteed across taps) still UPSERTs to the
        # same row. install_path on the Asset itself keeps original casing
        # for display.
        digest_input = f"{item_type}|{name_normalized}|{cellar_path.lower()}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"brew-ai-{digest}"
        desc_truncated: str | None
        if desc is not None and len(desc) > DESCRIPTION_TRUNCATE:
            desc_truncated = desc[:DESCRIPTION_TRUNCATE]
        else:
            desc_truncated = desc
        return Asset(
            id=asset_id,
            type="homebrew_ai_tool",
            parent_asset_id=None,
            name=name,
            version=version,
            install_path=cellar_path,
            source=SOURCE_NAME,
            current_state={
                "item_type": item_type,
                "full_name": full_name,
                "name_normalized": name_normalized,
                "version": version,
                "desc": desc_truncated,
                "homepage": homepage,
                "match_reason": match_reason,
                "tap": tap,
                "deprecated": deprecated,
                "dependencies": dependencies,
            },
            discovered_at=time.time(),
        )


__all__ = ["AI_KEYWORDS", "SOURCE_NAME", "HomebrewAiToolsSource"]
