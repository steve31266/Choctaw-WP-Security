# CoreGuard Version Compatibility

> Status: Draft scaffold. Freeze numbers before first joint Plugin + Desktop release.

## What Is Versioned

| Artifact | Identifier | Where exposed |
|---|---|---|
| CLI / JSON API contract | `api_version` (integer) | Every JSON envelope |
| Plugin package | `plugin_version` (SemVer) | Envelope + plugin headers |
| Heuristic packs | `pack_version`, `schema_version`, `engine_min_version` | Plugin-private; reflected on findings as metadata |
| Heuristic engine | engine SemVer (internal) | Not required for Desktop if finding contract is stable |
| Desktop application | Desktop SemVer | Desktop about / update channel |

Desktop compatibility decisions use **`api_version` first**, then optionally minimum `plugin_version` for known bugfix floors.

## Compatibility Guarantees (intended)

Within a given `api_version`:

- Existing commands keep their meaning.
- Existing JSON fields keep types and semantics.
- New commands, capabilities, and **additive** JSON fields are allowed.
- Consumers must ignore unknown fields and unknown capability IDs.

Breaking changes (rename/remove fields, change enums incompatibly, change command behavior) require a **new `api_version`**.

## Risk Enum Policy

- Engine / packs v1 emit only `critical` and `suspicious`.
- Before Plugin + Desktop ship together, freeze a **permanent published risk enum** under the CLI `api_version`.
- After freeze: additive only (new values require API bump or documented additive policy).
- Do not silently reinterpret existing risk strings.

## Deprecation Policy (expected)

1. Announce deprecated command/field in changelog and docs; mark in capabilities/metadata if useful.
2. Keep deprecated surface working for at least one Desktop major (or N plugin minors)—exact window TBD.
3. Remove only on next `api_version` bump.
4. Prefer parallel new fields over silent renames during overlap.

## Minimum Supported Versions

| Consumer | Minimum |
|---|---|
| Desktop ↔ Plugin CLI | TBD — e.g. Desktop 1.0 requires `api_version >= 1` and `plugin_version >= x.y.z` |
| Plugin WordPress/PHP | Per plugin readme (unchanged by this doc) |

Update this table when the first joint release is cut.

## Detection and Handling

### Desktop startup / site connect

1. Run `wp coreguard status --format=json` (or capabilities probe).
2. If command missing → treat as **no CoreGuard** (native audits only).
3. Parse `api_version` / `plugin_version`.
4. Apply matrix:

| Condition | Desktop behavior (expected) |
|---|---|
| API supported | Enable enhanced features for advertised capabilities |
| API newer than Desktop understands | Allow known subset; warn to update Desktop; do not guess new fields’ meaning beyond ignore-unknown |
| API older than Desktop minimum | Block enhanced features; prompt site owner to update CoreGuard plugin |
| JSON unparseable / unexpected envelope | Soft-fail site as degraded; log error; do not write settings |

### Plugin side

- Always emit `api_version` and `plugin_version`.
- Do not change envelope field meanings without bumping `api_version`.

## Pack / Engine vs CLI Versions

Pack and engine versions evolve inside the plugin. Desktop **must not** require pack file versions. Findings carry `pack_id` / `pack_version` for provenance and support, not for Desktop to load packs.

Fingerprints remain stable across pack content edits (pack versions are not part of fingerprints).

## Related Docs and Plans

- Decision recording policy: [docs/README.md](../docs/README.md)
- Finding / scan shapes: [JSON Schema](CoreGuard%20JSON%20Schema.md)
- Heuristics engine plan: [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md)

## Open Items

- Exact SemVer / integer policy for first freeze.
- Support window length for deprecations.
- Whether multiple `api_version` response modes are ever supported simultaneously.
- Capability `version` integers vs relying solely on global `api_version`.
