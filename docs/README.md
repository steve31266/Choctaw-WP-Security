# Sassh Documentation Library

Draft contracts and integration guides for the **Sassh** (Sassh Security) plugin’s public surfaces—especially the **WP-CLI JSON API** and **Sassh Desktop** (WPASSH). Filenames under this folder may still say `CoreGuard` until a dedicated docs rename pass.

## Source of truth

| Topic | Record decisions in |
|---|---|
| Findings System (persistence, dismissals, correlation, migration) | [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md) |
| CLI commands, options, exit codes | [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) |
| JSON envelope, finding/scan shapes, enums | [CoreGuard JSON Schema.md](CoreGuard%20JSON%20Schema.md) |
| Desktop ↔ plugin responsibilities, discovery | [CoreGuard Desktop Integration.md](CoreGuard%20Desktop%20Integration.md) |
| `api_version` / compatibility / risk enum freeze | [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md) |
| Feature inventory for clients | [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md) |
| Philosophy and document map | [CoreGuard CLI Overview.md](CoreGuard%20CLI%20Overview.md) |
| When those docs changed | [CHANGELOG.md](CHANGELOG.md) |

**Policy:** When we lock a decision about Desktop, the CLI API, JSON contracts, or versioning, update the appropriate file(s) in this folder **and** add a dated entry to [CHANGELOG.md](CHANGELOG.md) (summary, documents touched). Cursor plans (`.cursor/plans/`) may summarize and link here, but must not become a second conflicting source of truth for the public API.

This documentation changelog is separate from the plugin release [`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

Heuristic **engine/pack implementation** plans stay under `.cursor/plans/` (e.g. shared heuristics architecture, iframe tag inspection). Those plans must align findings with the common public finding envelope in [JSON Schema](CoreGuard%20JSON%20Schema.md) and the [Findings System](CoreGuard%20Findings%20System.md) contract (including canonical `risk_level` values and installation-scoped Multisite rules).

## Document map

| Document | Role |
|---|---|
| [README.md](README.md) | Library index and decision-recording policy |
| [CHANGELOG.md](CHANGELOG.md) | Dated history of documentation / decision changes |
| [CoreGuard CLI Overview.md](CoreGuard%20CLI%20Overview.md) | Purpose, philosophy, who uses the CLI |
| [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) | Command reference |
| [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md) | Findings persistence, dismissals, correlation, migration |
| [CoreGuard JSON Schema.md](CoreGuard%20JSON%20Schema.md) | Response and data contracts |
| [CoreGuard Desktop Integration.md](CoreGuard%20Desktop%20Integration.md) | SSH/WP-CLI integration model |
| [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md) | Versioning and incompatibility handling |
| [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md) | Capability IDs ↔ commands |

## Related product notes (plans)

- [CoreGuard-Findings-System.md](../.cursor/plans/CoreGuard-Findings-System.md) — working PRD copy; formal contract is [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md)
- [findings_phase_3x_index.plan.md](../.cursor/plans/findings_phase_3x_index.plan.md) — Phase 3.0–3.8 Findings migration plan index (local `.cursor/plans/`)
- [Plugin and Desktop Application Relationship](../.cursor/plans/Plugin%20and%20Desktop%20Application%20Relationship.md) — product philosophy (points here for formal API docs)
- [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md) — engine + pack data model
- [iframe_tag_inspection.plan.md](../.cursor/plans/iframe_tag_inspection.plan.md) — first heuristics family consumer

## Status

All files in this folder are **draft scaffolds** until `api_version` 1 is frozen for the first joint Plugin + Desktop release.

**Findings System:** Phase 1, 2, **3.0**, **3.1**, **3.2**, **3.3**, and **3.4** (persistence, Uploads + MU-Plugins + Verify Checksums + Exposed Files + Database options + WP-Cron, Network Admin shell, related-findings UI, `object_type=option` / `cron_event`) are implemented — see [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md) §11 and §18. Remaining scanner migrations are Phase **3.5–3.7**; prototype store wind-down is **3.8**. CLI/JSON/Desktop remain Phase 4/5.
