# Ruff warmup — deferred rules

**Status:** active
**Created:** 2026-05-25 (Component 2 of the spec-driven-enforcement PR)
**Owner:** Phase 3F cleanup sprint

## Purpose

Component 2 of the enforcement PR enabled an aggressive new ruff ruleset (17 families) but applied **only the 17-line safe-auto-fix subset** in the same commit. The dispatch's 100-line gate was deliberate — a 500+ line mechanical churn would distort the architect's review of the rule-enable diff itself and absorb review attention that should land on the conceptual change.

The remaining violations are deferred here, split into two categories:

- **Category A — Genuine technical debt.** Rules where the violations represent real cleanup work. Target: Phase 3F refactor sprint.
- **Category B — Likely false positives or intentional patterns.** Rules where the violation count probably reflects the new ruleset misreading Vigil's actual code. Target: Phase 3F audit, with disposition (permanent ignore-with-rationale, or escalate to enforced).

The warmup list **shrinks** over time. New rules from later ruff versions can be added here when they first land, but no rule should accumulate violations vs. its baseline count without justification. `scripts/check_ruff_progress.py` (planned, Phase 3F) will track per-rule trends week over week.

## Category A — Genuine technical debt (Phase 3F cleanup sprint)

| Rule | Count | Auto-fix? | Est. effort | Sample violation |
|---|---:|:---:|:---:|---|
| `PLC0415` | 552 | no | large | lazy `import` inside functions across `monitor.py`, `watch.py`, `wizard.py` — some intentional (optional deps), some real anti-patterns |
| `BLE001` | 164 | no | large | `except Exception:` in scanner loops where any single failure must not crash the daemon. Mix of legitimate broad-catch and real anti-patterns. |
| `S110` | 71 | no | medium | `try: ... except: pass` — most are scanner cycles that intentionally swallow individual-record errors; some hide real bugs. |
| `E501` | 46 | no | small | long lines (URLs, regex patterns, hardcoded headers). Was previously ignored; now exposed. Most are mechanical wraps. |
| `PLW1510` | 39 | no | medium | `subprocess.run(...)` without `check=True`. Mostly intentional in status probes; should switch to explicit `check=False` with rationale. |
| `PTH123` | 30 | no | small | `open(path)` — mechanical migration to `Path.open()` per CLAUDE.md "Mandatory patterns" preference for pathlib. |
| `PLR0912` | 25 | no | large | too-many-branches. Mostly in `monitor.py::main` and `_process_record` — the M6 split (planned) will fix this naturally. |
| `TRY300` | 23 | no | small | `try/except/else` reorganization. Mechanical. |
| `PLR0915` | 19 | no | medium | too-many-statements (≤20 but still a complexity signal). Same target as PLR0912 — M6 monitor.py split. |
| `PTH101` | 14 | no | small | `os.chmod` → `Path.chmod`. Mechanical, scoped to `security.py`. |
| `PERF401` | 13 | no | small | manual list-comp where a comprehension would be clearer. Mechanical. |
| `SIM117` | 11 | unsafe | small | multiple `with` statements → combined `with a, b:`. Auto-fixable but ruff considers it unsafe (semantic reorder possible if one of the managers has a side-effecting `__init__`). |
| `SIM105` | 10 | no | small | `try/except/pass` → `contextlib.suppress`. Stylistic. |
| `PLR0911` | 7 | no | medium | too-many-return-statements. Same M6 target. |
| `PLW0603` | 7 | no | medium | `global` statement usage in module-level scanner state. Replace with class encapsulation. |
| `PLW2901` | 6 | no | small | for-loop variable shadowed inside loop. Mechanical rename. |
| `S310` | 5 | no | small | `urllib.urlopen` flagged but every call is to a hardcoded loopback URL or trusted upstream (already documented in bandit ignore list at `pyproject.toml:92`). Mechanical: add per-line `# noqa: S310` with the same rationale. |
| `PTH110` | 3 | no | small | `os.path.exists` → `Path.exists`. Mechanical. |
| `DTZ005` | 2 | no | small | `datetime.now()` → `datetime.now(timezone.utc)`. Real bug surface — naive datetimes are a CLAUDE.md forbidden pattern. **Fix in Phase 3F before any other cleanup.** |
| `PLW0602` | 2 | no | small | global-variable-not-assigned. Mechanical. |
| `PTH202` | 2 | no | small | `os.path.getsize` → `Path.stat().st_size`. Mechanical. |
| `S314` | 2 | no | small | `xml.etree` flagged; we parse trusted cobertura XML (our own coverage output). Add `# noqa: S314` with rationale. |
| `PTH108` | 1 | no | small | `os.unlink` → `Path.unlink`. |
| `PTH109` | 1 | no | small | `os.getcwd` → `Path.cwd`. |
| `PTH111` | 1 | no | small | `os.path.expanduser` → `Path.home()`. |
| `RUF012` | 1 | no | small | mutable class default. Real bug surface; fix in Phase 3F before any other cleanup. |
| `RUF034` | 1 | no | small | useless if/else. Mechanical. |
| `SIM102` | 1 | no | small | collapsible if. Mechanical. |
| `SIM103` | 1 | no | small | needless-bool. Mechanical. |
| `SIM115` | 1 | no | small | open file without context handler. Real bug surface. |

**Subtotal: ~1083 violations across 29 rules.** Estimated effort: 2-3 days of focused cleanup work in Phase 3F.

Two entries above are flagged as **real bug surface** (DTZ005 — naive datetimes; RUF012 — mutable class default; SIM115 — file handle leak): land these first in Phase 3F before the mechanical cleanup so they don't get lost in the noise.

## Category B — Likely false positives or intentional patterns (Phase 3F audit)

| Rule | Count | Hypothesis | Sampling plan |
|---|---:|---|---|
| `S607` | 40 | Intentional: `osascript`, `networksetup`, `security` from system PATH per macOS conventions. The full-path alternative would be `/usr/bin/osascript` which Apple deprecated in some sandbox contexts. | Read 5 random `subprocess.run([...])` calls flagged by S607; if all are macOS system tools by base name, add to ignore list with rationale comment. |
| `S608` | 33 | Likely false positive: SQL strings in this codebase are parameterized templates with `?` placeholders (the CLAUDE.md mandatory pattern). Ruff appears to flag any multi-line SQL string as "could be" string-concatenation. | Read 5 random S608 violations; if all use `?` placeholders + parameter tuples to `db.execute(sql, params)`, add to ignore list. |
| `S603` | 32 | Almost certainly false positive: Vigil's pattern is argv lists `subprocess.run(["cmd", "arg"], check=...)` which is the **secure** form. The rule's documentation explains it flags `shell=True` cases, but in practice it appears to fire on every `subprocess.run` call. | Read 5 random S603 violations; confirm all use argv lists (not `shell=True`). If so, add to ignore list with link to the false-positive Bandit issue this rule descends from. |
| `S311` | 14 | Likely false positive in tests: `random.random()` / `random.choice()` in test fixtures (not crypto). The S rule family is already off in tests via `per-file-ignores`, but S311 may fire from src/ too. | Audit src/ S311 hits separately; if all are non-crypto (e.g., jitter in retry backoff), ignore in src as well. |
| `S105` | 3 | Likely false positive: hardcoded "password" / "token" / "secret" strings flagged as credentials, but in this codebase they're usually the *names* of configuration keys, not actual secrets. | Read all 3 violations; if they're variable names or key strings (`"dashboard_token": ...`), add `# noqa: S105` per-line with rationale. |
| `S112` | 6 | Mixed: `try/except/continue` in scanner loops where continuing on per-record errors is intentional. Some of these may be real anti-patterns; some are legitimate. | Audit each; the legitimate ones get `# noqa: S112` with rationale, real ones go into Category A for cleanup. |
| `S606` | 2 | Likely false positive (start-process-with-no-shell — paradoxically the secure form). Same diagnosis as S603. | Confirm + ignore. |

**Subtotal: ~130 violations across 7 rules.** Estimated audit effort: 4-6 hours total. Disposition either:
- Add to `[tool.ruff.lint.ignore]` in `pyproject.toml` with a multi-line rationale comment (like the existing `B008` comment pattern that was just removed), OR
- Move to Category A if the audit shows the violations are real after all.

**Important: do not pre-emptively add Category B rules to the ignore list in this PR.** That requires the audit work; until the sampling confirms the hypothesis, the rules stay surfaced (warmup-mode, advisory-not-blocking) so future violations remain visible.

## How this list shrinks

1. **Phase 3F refactor sprint** picks up Category A rules in size order (small → medium → large). Each cleanup PR removes the corresponding row from the table here.
2. **Category B audit** is a single Phase 3F task: read the sample, decide ignore-vs-cleanup, update `pyproject.toml` and this doc atomically.
3. **`scripts/check_ruff_progress.py`** (planned, Phase 3F) automates the weekly count check. If any rule's count grows vs. baseline, that's a regression — the CI gate fires.

The warmup is **not** a permanent home for any rule. Every entry has an exit path: either Category A → cleaned up, or Category B → audited and resolved.
