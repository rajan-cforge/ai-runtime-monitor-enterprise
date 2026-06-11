# Dependency rationale

**Status:** active
**Last updated:** 2026-05-25
**Required by:** the spec-requirements YAML rule (`requires_doc: "docs/spec/dependency-rationale.md"`, severity BLOCK). Every PR that modifies `pyproject.toml`'s `dependencies` or `optional-dependencies` arrays must also update this document.

## 1. Purpose

This document records the decision history for every Python dependency Vigil ships with — both inclusions and explicit rejections. The goal is twofold:

- **Auditability.** Anyone reviewing the dependency set should be able to answer "why this library and not that one?" without having to dig through old PR threads or maintainer memory.
- **Supply-chain hygiene.** Recording the why-not is as important as recording the why. Declined tools (Trivy, Codecov, GitPython, etc.) often resurface in future "should we add this?" conversations; capturing the original reasoning prevents re-litigating settled decisions and keeps the dependency surface intentionally small.

The spec-requirements YAML treats a `pyproject.toml` change without a matching `dependency-rationale.md` update as a BLOCK-severity violation — the CI gate fires, and the PR cannot merge until either the doc is updated or the dep change is reverted. This document existing on `main` is therefore load-bearing for the entire enforcement layer.

## 2. Current production dependencies

The runtime dependency surface (from `pyproject.toml` `[project] dependencies`) is intentionally minimal — three direct deps, all first-party or PSF-blessed, all chosen specifically for the endpoint-observability problem Vigil solves.

- **`cryptography>=42.0`** — used by `security.py` for the per-install CA generation (X.509 with NameConstraints scoping the CA to AI domains only, per the C4 architectural fix) and by `mitmproxy` transitively. The PSF/PyCA-maintained `cryptography` package is the only mature option in the Python ecosystem for X.509 with NameConstraints — `pyopenssl` predates the constraint API, and pure-Python alternatives (`pem`, `asn1crypto`) don't ship a high-level signer. Alternatives considered: pyOpenSSL (older API, lacks NameConstraints high-level support), shelling out to `openssl` CLI (subprocess surface, version drift across user machines).

- **`mitmproxy>=10.0`** — the HTTPS interception engine. mitmproxy is the canonical Python HTTPS-MITM toolkit; it ships an addon framework, certificate management, and a flow API that map directly onto Vigil's interception needs. **Promoted to a base dependency in PR #52 (was the `[watch]` optional extra).** Rationale: every documented use of Vigil — PRD §4 capabilities, brand-site hero copy, agent-detection design doc — treats SSL inspection of AI API traffic as the central capability. The optional-install model produced a silent-failure footgun where `pip install ai-runtime-monitor` shipped a half-working product (mitmproxy missing → proxy fails to start → system proxy auto-disabled by daemon cleanup → user sees no proxy and no helpful error). Surfaced during the new-laptop install verification on 2026-05-25. Trade-off: install size grows ~50 MB. Acceptable for a security product — comparable products are 80–500 MB (Trivy, Snyk CLI, CrowdStrike). Pinning at `>=10.0` because the addon API stabilized in v10. Alternatives considered: `proxy.py` (smaller surface, smaller community, no addon ecosystem), writing a custom MITM with `aiohttp` (re-implementing certificate trust dance and CONNECT tunneling is a security footgun).

- **`psutil>=5.9.0`** — process and network enumeration in `monitor.py::ProcessScanner` and `NetworkMonitor`. Cross-platform (macOS, Linux), well-maintained, idiomatic for system-monitoring tooling. Alternatives considered: `os.popen("ps aux")` (subprocess, brittle parsing, no per-process socket data), platform-specific libraries (`procfs` on Linux, native APIs on macOS — defeats portability).

- **`watchdog>=3.0`** — filesystem-event observation for `monitor.py::JSONLSessionWatcher` (Claude Code transcripts) and `FileActivityHandler` (project directories). On macOS it sits on top of FSEvents; on Linux on top of inotify. Alternatives considered: polling (CPU overhead at the sub-second responsiveness Vigil needs), platform-specific bindings (loses portability).

- **`cvss>=3.0`** — used by `attack_surface/cves/dispatcher.py` to parse the CVSS vector strings that OSV.dev returns in `severity[].score` (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) into the numeric base score that `compute_risk_score` consumes via its `cves: list[{"cvss": float}]` argument. Pure-Python implementation by RedHat Product Security, currently the canonical Python parser for CVSS:2.x and CVSS:3.x vector strings (FIRST's CVSS:4.0 calculator is a separate effort the library has not yet absorbed; v4.0 advisories are rare enough today that the dispatcher's "no parseable severity → cvss=0.0 fallback" path is the right interim). Alternatives considered: manual implementation of the CVSS:3.1 base-score formula (the 8-metric exploitability + impact equation per FIRST spec — non-trivial code surface and one more thing to keep verified against the spec when CVSS:4.0 ships), shelling out to `nvd-tools` (a Go CLI, adds a binary dep), pinning to the NVD's pre-computed score field (OSV doesn't always populate it and NVD lags by days-to-weeks). Phase A §8 of the v0.2.2 P4.1 design doc ratified this dep on 2026-06-10.

## Optional extras

- **`[watch]`** — retained as an **empty no-op alias** so existing install commands `pip install "ai-runtime-monitor[watch]"` keep working without producing a "no such extra" error. The actual `mitmproxy` dependency moved to the base list in PR #52 (see the "Current production dependencies" section). Removable in v0.3.

- **`matplotlib>=3.5` (extra: `plot`)** — used by `watch.py::run_plot` for the optional `claude-watch --plot` analytical view (token usage / cost / latency over time). The `[plot]` extra exists because matplotlib's install footprint (numpy, freetype, etc.) is significant and most operators never invoke the plot mode. Alternatives considered: `plotly` (heavier; web-stack JS dependency), generating CSV for spreadsheet plotting (loses the one-command analytical loop the feature is built for).

- **`sqlcipher3-binary>=0.5` (extra: `security`)** — optional encryption-at-rest for `monitor.db`. Activates when `HAS_SQLCIPHER` is True at import time; otherwise plain `sqlite3` + chmod 600 + FileVault. The dual-path design lets users opt into transparent DB encryption without paying the binary-install cost when they don't need it. Alternatives considered: PyCryptodome with manual page-level encryption (re-implementing SQLCipher poorly), full-disk encryption only (insufficient for shared-disk threat models).

## 3. Considered and declined

Tools the team or community has surfaced as "should we add this?" and the documented reasoning for declining. Listed here so the next person asking the same question gets the same answer without re-litigation.

- **Trivy.** Not adopted. Trivy is a container image scanner; Vigil ships no container image. Python-specific tooling (`pip-audit` for CVE scanning, `bandit` for SAST) covers the relevant surface for our distribution model (PyPI sdist + wheel). Reconsider only when Vigil itself starts shipping container images (not in the current roadmap).

- **Codecov.** Not adopted. The per-file coverage ratchet shipped in PR #27 enforces coverage discipline more strictly than Codecov's soft warnings, keeps the test-execution data in-tree (no SaaS dependency), and explicitly avoids the third-party SaaS exposure that Codecov itself demonstrated in CVE-2021-32699 (the 2021 supply-chain incident where a malicious bash uploader was injected into Codecov's CI uploader for ~2 months and exfiltrated CI secrets from thousands of repos). The PR-#27 ratchet covers the same product surface (don't let coverage drift down) with strictly less attack surface.

- **GitPython.** Not adopted. Direct `subprocess.run(["git", ...])` invocation is sufficient for the scripts that need git access (`scripts/coverage_ratchet.py`, `scripts/dev/pre_pr_review.sh`), and avoids a heavyweight dependency with a non-trivial history of CVEs (GitPython has had multiple command-injection issues over the years; the project lives in maintenance mode). The subprocess path uses argv lists (per CLAUDE.md mandatory pattern), so the command-injection surface is closed at the call site rather than delegated to a library.

- **`tomli` / `tomllib` (manual install).** Not adopted as an explicit dependency. Python 3.11+ ships `tomllib` in stdlib; earlier versions can fall back to the small `tomli` package, but the codebase currently doesn't parse TOML at runtime (only `pyproject.toml` at build time, handled by `setuptools`). When `config.py` grows runtime TOML support, the conditional `tomllib` (3.11+) / `tomli` (<=3.10) shim will be added with rationale here.

- **`requests` / `httpx` (runtime).** Not adopted at the base runtime layer. Vigil's network code uses `urllib.request` from stdlib for the few outbound HTTP calls (threat-intel feeds, OSV, PyPI metadata) — sufficient for the request volumes Vigil generates and avoids a dependency for a feature that doesn't need its convenience. The `[watch]` extra pulls in `tornado` transitively via mitmproxy, but that's mitmproxy's runtime, not ours. Adopt `httpx` if/when a future feature needs streaming or HTTP/2.

## 4. Rules for adding a new dependency

When proposing a new dependency in a PR:

1. **Add an entry to Section 2 or 3 of this document.** Include the role the dep plays (one paragraph), the alternatives considered (one short list with one-line reasoning per alternative), and the reason this one won. The entry must be in the same PR that touches `pyproject.toml` — the spec-requirements gate will block otherwise.

2. **Verify the license is permissible.** The license-gate CI workflow (`.github/workflows/ci-supply-chain.yml`) automatically blocks GPL/AGPL family licenses for runtime deps. The reviewer still confirms — license-gate is mechanical and can be evaded by transitive deps. Apache 2.0, MIT, BSD-2/3-Clause, ISC, LGPL (linking only) are pre-approved.

3. **Verify the dep is actively maintained.** Commits within the last 12 months, or explicit justification for adopting a low-activity dep (e.g., a stdlib backport that's "done" by design).

4. **Consider supply-chain risk.** First-party (PSF, requests, cryptography, attrs) and well-established community projects (pytest, watchdog, psutil) are low-risk. Single-maintainer packages, packages from new authors, packages with sparse download counts, or packages that recently changed maintainership require stronger justification — including a brief threat-model note in the same PR (typosquat risk? upstream-takeover risk? what's the blast radius if this dep ships malware?). The SECURITY-MANIFEST §V14.2 controls back-stop this at runtime, but the per-PR audit is cheaper than a post-merge cleanup.
