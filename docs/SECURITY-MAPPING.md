# Vigil — Security Standards Mapping

Per directive line 209 (`v022-implementation-directive-v1-LOCKED.md`):

> **P5.4** (C1): Standards mapping documentation. Each curated rule
> cites NIST CSF, CIS Controls, MITRE ATT&CK. Documented in new
> `docs/SECURITY-MAPPING.md`.

This document is the standards reference for Vigil's nine curated
risk rules. The source-of-truth for every rule (id, pattern, modifier,
explanation, framework citations) is
[`config/risk-rules.yaml`](../config/risk-rules.yaml); this file is a
derived view of that data. If the two ever disagree, the YAML wins —
see "Drift policy" at the bottom.

## How risk modifiers compose

Vigil computes a base risk score from four weighted factors per
spec §6.1 (`max_cve_severity`, `permission_breadth`,
`integration_sensitivity`, `activity_recency`). Curated rules each
declare an integer `modifier` in the range `[-10, +30]` per spec §6.2.
A single rule's modifier wins per the max-wins composition:

    final_risk = clamp(0, 100, base_risk + max(rule_modifiers))

Every rule that matched the asset (winning + suppressed alike) shows
in the dashboard's per-asset breakdown popover, so an operator can see
why a score landed where it did and which control the standards
bodies expect to mitigate the abuse.

Citation discipline (set at P2.5 ratification 2026-06-07): name the
**most specific** subcategory / technique / control whose protective
action would directly prevent the abuse the rule models, not a parent
category.

## Rule-by-rule mapping

| # | Rule ID | Pattern (ontology tags) | Modifier | NIST CSF v1.1 | CIS Controls v8 | MITRE ATT&CK |
|---|---|---|---:|---|---|---|
| 1 | `rule_shell_filesystem_combo_001` | `shell_execute` AND `file_system_write` | +10 | PR.PT-3 | CIS-2.5 | T1059 |
| 2 | `rule_shell_network_combo_001` | `shell_execute` AND `network_unrestricted` | +15 | PR.PT-4 | CIS-12.2 | T1071 |
| 3 | `rule_exfil_capable_001` | `data_exfiltration_capable` (spec §5.4 derived) | +15 | PR.DS-5 | CIS-3.13 | T1567 |
| 4 | `rule_secrets_network_001` | `secrets_access` AND `network_unrestricted` | +20 | PR.DS-5 | CIS-3.11 | T1567 |
| 5 | `rule_shell_secrets_combo_001` | `shell_execute` AND `secrets_access` | +20 | PR.AC-4 | CIS-6.8 | T1552 |
| 6 | `rule_filesystem_read_network_001` | `file_system_read` AND `network_unrestricted` | +15 | PR.DS-5 | CIS-3.13 | T1567 |
| 7 | `rule_code_execution_network_001` | `code_execution` AND `network_unrestricted` | +15 | PR.PT-4 | CIS-2.7 | T1071 |
| 8 | `rule_unknown_capability_sharpener_001` | `unknown_capability: true` | +5 | ID.SC-2 | CIS-2.1 | T1195 |
| 9 | `rule_exfil_capable_unrecognized` | `unknown_capability: true` AND `secrets_access` | +20 | PR.DS-5 | CIS-6.6 | T1552 |

### Why each combination matters

The narrative for each rule is quoted verbatim from its `explanation`
field in `config/risk-rules.yaml` — by design, so this document
cannot drift from the rule it describes.

**1. `rule_shell_filesystem_combo_001`** (PR.PT-3 / CIS-2.5 / T1059) —
Asset can execute shell commands AND write to the host file system.
This combination enables dropper / persistence patterns: a compromised
or coerced asset can stage payloads on disk via the file system and
invoke them via the shell.

**2. `rule_shell_network_combo_001`** (PR.PT-4 / CIS-12.2 / T1071) —
Asset can execute shell commands AND reach arbitrary network hosts.
The shell-plus-egress combination is the canonical command-and-control
surface: outbound traffic carries arbitrary shell results, inbound
traffic carries arbitrary shell input.

**3. `rule_exfil_capable_001`** (PR.DS-5 / CIS-3.13 / T1567) —
Asset is data-exfiltration capable per spec §5.4 derivation:
(secrets_access OR file_system_read) AND (network_unrestricted OR
network_scoped). A single compromised request from such an asset
can ship sensitive data to an attacker-controlled endpoint.

**4. `rule_secrets_network_001`** (PR.DS-5 / CIS-3.11 / T1567) —
Asset can read secrets (credentials, tokens, cookies) AND reach
arbitrary network hosts. This is the credential-exfiltration surface:
a single coerced request egresses credentials to an attacker
endpoint, after which the attacker reuses the credential at will.

**5. `rule_shell_secrets_combo_001`** (PR.AC-4 / CIS-6.8 / T1552) —
Asset can execute shell commands AND read secrets. Shell access
expands the secret-access reach far beyond declared APIs: a shell
can grep config files, env vars, keychains, and dotfiles for any
secret the asset's process can read, violating least privilege.

**6. `rule_filesystem_read_network_001`** (PR.DS-5 / CIS-3.13 / T1567) —
Asset can read host files AND reach arbitrary network hosts. The
read-plus-egress combination is a generic data-exfil surface: any
file the asset's process can read may be shipped to an
attacker-controlled endpoint.

**7. `rule_code_execution_network_001`** (PR.PT-4 / CIS-2.7 / T1071) —
Asset can execute arbitrary code in the host AI agent's process
AND reach arbitrary network hosts. The combined capability is the
operational profile of a remote-access tool: inbound network can
deliver code; the asset executes it; outbound network exfiltrates
results.

**8. `rule_unknown_capability_sharpener_001`** (ID.SC-2 / CIS-2.1 / T1195) —
Asset's capabilities are not recognized by Vigil's ontology (the
spec §6.8 unknown-capability path fired). Sharpens the unknown-
capability MEDIUM floor (40) into the upper half of MEDIUM, since
an unrecognized component is a supply-chain visibility gap until
v0.3 introspection or a manifest analysis lands.

**9. `rule_exfil_capable_unrecognized`** (PR.DS-5 / CIS-6.6 / T1552) —
Asset is unrecognized by Vigil's ontology AND declares
secrets_access via its installation surface. An unrecognized
component with credential access is the worst pairing of the
unknown-capability path: Vigil cannot reason about how the
component uses those credentials, and the historical compromise
pattern (typosquats, dependency confusion) targets exactly this
surface. Composes with the spec §6.8 floor (40) per §6.9
re-assertion to land at HIGH (60).

## Reverse index — NIST CSF v1.1

| Subcategory | Rules |
|---|---|
| ID.SC-2 (Suppliers and partners are identified, prioritized, assessed) | r8 |
| PR.AC-4 (Access permissions managed; least privilege) | r5 |
| PR.DS-5 (Protections against data leaks) | r3, r4, r6, r9 |
| PR.PT-3 (Principle of least functionality) | r1 |
| PR.PT-4 (Communications and control networks protected) | r2, r7 |

## Reverse index — CIS Controls v8

| Control | Rules |
|---|---|
| CIS-2.1 (Establish and Maintain a Software Inventory) | r8 |
| CIS-2.5 (Allowlist Authorized Software) | r1 |
| CIS-2.7 (Allowlist Authorized Scripts) | r7 |
| CIS-3.11 (Encrypt Sensitive Data) | r4 |
| CIS-3.13 (Deploy a Data Loss Prevention Solution) | r3, r6 |
| CIS-6.6 (Manage Authentication Systems) | r9 |
| CIS-6.8 (Define and Maintain Role-Based Access Control) | r5 |
| CIS-12.2 (Establish and Maintain a Secure Network Architecture) | r2 |

## Reverse index — MITRE ATT&CK

| Technique | Rules |
|---|---|
| T1059 (Command and Scripting Interpreter) | r1 |
| T1071 (Application Layer Protocol — C2) | r2, r7 |
| T1195 (Supply Chain Compromise) | r8 |
| T1552 (Unsecured Credentials) | r5, r9 |
| T1567 (Exfiltration Over Web Service) | r3, r4, r6 |

## Drift policy

`config/risk-rules.yaml` is the source-of-truth. The schema gate
(`scripts/check_risk_rules_schema.py`) accepts `cis_controls`
citations today but does not yet *require* the union of all three
frameworks (NIST CSF + CIS Controls + MITRE ATT&CK); a follow-up
ratchet will tighten the gate so any future rule that lands with
fewer than three citations fails CI before merge. Until that ratchet
ships, the curated-rule directive (directive line 209) is the
manual invariant — any new rule MUST cite all three frameworks at
the YAML edit, and this doc MUST be regenerated as part of the
same PR.

If a citation in this doc disagrees with the YAML, the YAML wins.

## References

- Directive: `~/Documents/vigil-notes/v022-implementation-directive-v1-LOCKED.md`
  lines 209 (P5.4 deliverable) + 1543–1547 (doc requirements).
- Spec: `~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md`
  §6.2 (rule schema + max-wins), §6.4 (breakdown popover), §6.8
  (unknown-capability floor).
- NIST CSF v1.1: https://www.nist.gov/cyberframework
- CIS Controls v8: https://www.cisecurity.org/controls
- MITRE ATT&CK Enterprise: https://attack.mitre.org/
