# Documentation Changelog

Decision and documentation history for files under [`docs/`](README.md).

This log is **not** the plugin release changelog ([`CHANGELOG.md`](../CHANGELOG.md) at the repo root). Use this file to record when CLI, Desktop, JSON schema, versioning, or related docs were added or changed.

## Entry format

```markdown
## YYYY-MM-DD HH:MM TZ

**Summary:** One or two sentences describing what changed and why.

**Documents:**
- path/relative/to/docs/or/repo — added | updated | deleted — brief note
```

Newest entries first.

---

## 2026-07-15 21:00 CDT

**Summary:** Directory Browsing scan now uses the standard findings report contract (Risk/Status/eye-expand, per-folder HTTP tests of plugins/themes/uploads roots, optional Nginx leftover `.htaccess` Info row). Capability key unchanged.

**Documents:**
- `docs/CoreGuard Capabilities.md` — updated — clarified `scan.directory_browsing` scope
- `CHANGELOG.md` — updated — Unreleased Directory Browsing migration note
- `README.md` — updated — Directory Browsing feature blurb

## 2026-07-12 13:50 CDT

**Summary:** Added always-apply Cursor agent rule so Desktop/CLI decisions update `docs/` and `docs/CHANGELOG.md`.

**Documents:**
- `.cursor/rules/agent.mdc` — added — alwaysApply docs decision + changelog policy

## 2026-07-12 13:45 CDT

**Summary:** Established `docs/` as the source of truth for Desktop and CLI API decisions; added a library index and cross-links so Cursor plans point at formal contracts instead of duplicating them. Seeded this documentation changelog.

**Documents:**
- `docs/README.md` — added — library index and decision-recording policy
- `docs/CHANGELOG.md` — added — this file
- `docs/CoreGuard CLI Overview.md` — updated — Source of Truth section; document map includes README
- `docs/CoreGuard Desktop Integration.md` — updated — Related Plans; packs private / incomplete≠clean already present
- `docs/CoreGuard JSON Schema.md` — updated — Related Plans pointing at heuristics architecture
- `docs/CoreGuard Version Compatibility.md` — updated — Related Docs and Plans
- `.cursor/plans/shared_heuristics_architecture.plan.md` — updated — Desktop/CLI section defers to `docs/` as canonical
- `.cursor/plans/Plugin and Desktop Application Relationship.md` — updated — points formal contracts to `docs/`

## 2026-07-12 (earlier)

**Summary:** Draft scaffold set created for the CoreGuard WP-CLI JSON API and Desktop integration (envelope, commands, capabilities, versioning, finding/scan shapes aligned with heuristics architecture decisions). Exact authoring time not recorded; treat as the initial draft baseline for this library.

**Documents:**
- `docs/CoreGuard CLI Overview.md` — added
- `docs/CoreGuard CLI API.md` — added
- `docs/CoreGuard JSON Schema.md` — added
- `docs/CoreGuard Desktop Integration.md` — added
- `docs/CoreGuard Version Compatibility.md` — added
- `docs/CoreGuard Capabilities.md` — added
