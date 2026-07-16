# CoreGuard Documentation Library

Draft contracts and integration guides for the CoreGuard plugin’s public surfaces—especially the **WP-CLI JSON API** and **CoreGuard Desktop** (WPASSH).

## Source of truth

| Topic | Record decisions in |
|---|---|
| CLI commands, options, exit codes | [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) |
| JSON envelope, finding/scan shapes, enums | [CoreGuard JSON Schema.md](CoreGuard%20JSON%20Schema.md) |
| Desktop ↔ plugin responsibilities, discovery | [CoreGuard Desktop Integration.md](CoreGuard%20Desktop%20Integration.md) |
| `api_version` / compatibility / risk enum freeze | [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md) |
| Feature inventory for clients | [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md) |
| Philosophy and document map | [CoreGuard CLI Overview.md](CoreGuard%20CLI%20Overview.md) |
| When those docs changed | [CHANGELOG.md](CHANGELOG.md) |

**Policy:** When we lock a decision about Desktop, the CLI API, JSON contracts, or versioning, update the appropriate file(s) in this folder **and** add a dated entry to [CHANGELOG.md](CHANGELOG.md) (summary, documents touched). Cursor plans (`.cursor/plans/`) may summarize and link here, but must not become a second conflicting source of truth for the public API.

This documentation changelog is separate from the plugin release [`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

Heuristic **engine/pack implementation** plans stay under `.cursor/plans/` (e.g. shared heuristics architecture, iframe tag inspection). Those plans must align findings with the JSON Schema finding object so future CLI exposure stays consistent.

## Document map

| Document | Role |
|---|---|
| [README.md](README.md) | Library index and decision-recording policy |
| [CHANGELOG.md](CHANGELOG.md) | Dated history of documentation / decision changes |
| [CoreGuard CLI Overview.md](CoreGuard%20CLI%20Overview.md) | Purpose, philosophy, who uses the CLI |
| [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) | Command reference |
| [CoreGuard JSON Schema.md](CoreGuard%20JSON%20Schema.md) | Response and data contracts |
| [CoreGuard Desktop Integration.md](CoreGuard%20Desktop%20Integration.md) | SSH/WP-CLI integration model |
| [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md) | Versioning and incompatibility handling |
| [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md) | Capability IDs ↔ commands |

## Related product notes (plans)

- [Plugin and Desktop Application Relationship](../.cursor/plans/Plugin%20and%20Desktop%20Application%20Relationship.md) — product philosophy (points here for formal API docs)
- [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md) — engine + pack data model
- [iframe_tag_inspection.plan.md](../.cursor/plans/iframe_tag_inspection.plan.md) — first heuristics family consumer

## Status

All files in this folder are **draft scaffolds** until `api_version` 1 is frozen for the first joint Plugin + Desktop release.
