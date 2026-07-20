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

## 2026-07-19 19:20 CDT

**Summary:** Plugin release **1.9.3** — Sassh public rebrand (`sassh.php`, admin UI), Findings System Phase 1/2 (Uploads reference), and related docs status updates recorded for this release.

**Documents:**
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3`
- `CHANGELOG.md` — updated — `[1.9.3] - 2026-07-19` release notes (from Unreleased)
- `README.md` — updated — 1.9.3 changelog summary
- `docs/CoreGuard Findings System.md` — already updated — Phase 1/2 complete status (§18)
- `docs/README.md` — already updated — Findings Phase 1/2 status note

## 2026-07-19 19:15 CDT

**Summary:** Recorded Findings Phase 1/2 as implemented and QA’d; corrected Phase 2 Uploads risk to `warning` + `needs_review`; marked Phase 3 (Network Admin + further scanner migrations) as the next deliverable; noted Multisite Network Admin UI remains deferred.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — document status, §18 phases, §19 Uploads QA note
- `docs/README.md` — updated — Findings Phase 1/2 status note
- `.cursor/plans/CoreGuard-Findings-System.md` — synced

## 2026-07-19 18:00 CDT

**Summary:** Public product rebrand from CoreGuard to **Sassh** / **Sassh Security** (Site Audit over SSH). Admin UI strings, page slugs (`sassh*`), header logo, and main bootstrap file (`sassh.php`) updated. Text Domain, option keys, AJAX actions, PHP class names, and formal `docs/CoreGuard*.md` filenames intentionally unchanged in this pass.

**Documents:**
- `README.md` — updated — product name, install/activate, admin menu labels, project tree (`sassh.php`)
- `docs/CHANGELOG.md` — updated — this entry
- `docs/README.md` — updated — library index product wording (contract filenames still `CoreGuard *.md` for now)
- `.cursor/plans/sassh_public_rebrand_7a87c1c6.plan.md` — implementation plan for the rebrand

## 2026-07-17 20:30 CDT

**Summary:** Locked centralized Sassh authorization: single-site `manage_options`; Multisite `manage_network_options` (Super Admins only); nonces on state-changing admin actions; network-wide Findings must not be exposed to ordinary subsite admins (Network Admin registration; no interim subsite-admin shortcut).

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §3.10 authorization boundary
- `.cursor/plans/findings_phase_1_2_a6eb0844.plan.md` — already reflected authorization correction

## 2026-07-17 18:15 CDT

**Summary:** Confirmed locked user-facing label **Review Not Needed** for machine key `no_action_needed` (prototype “No Action Needed” strings update at Findings UI migration).

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §3.3, §18 Phase 2, §21 already-locked list
- `.cursor/plans/CoreGuard-Findings-System.md` — synced

## 2026-07-17 18:10 CDT

**Summary:** Deferred Home snapshot-versus-current UX and notification recipient/template/frequency decisions until after the Findings System is fully implemented; they must not block Phase 1/2.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §12.4, §12.5, §21 deferred-decision wording
- `.cursor/plans/CoreGuard-Findings-System.md` — synced

## 2026-07-17 18:00 CDT

**Summary:** Amended Findings System for installation-scoped Multisite (network-wide CoreGuard; `blog_id` in object identity), five canonical `risk_level` values with default classification mapping, Clear History/baseline removal on migration, fresh-start prototype cutover (no path-only dismissal migration), and architectural requirements for future Scan Site / scheduled scans / email / Home without expanding Phase 1/2 scope.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — Multisite, risk, Clear History, legacy cutover, §12 future consumers, Phase 1/2 attribution minimum
- `docs/CoreGuard JSON Schema.md` — updated — locked five `risk_level` values; Site Identity open item wording
- `docs/CoreGuard CLI API.md` — updated — `--risk` canonical values
- `docs/CoreGuard Desktop Integration.md` — updated — Multisite and future consumer notes
- `docs/CoreGuard Version Compatibility.md` — updated — five-value `risk_level` enum policy
- `docs/README.md` — updated — Findings/Multisite/risk alignment note for heuristics plans
- `.cursor/plans/CoreGuard-Findings-System.md` — synced with canonical docs copy

## 2026-07-17 16:05 CDT

**Summary:** Promoted the finalized CoreGuard Findings System PRD into `docs/`. Reconciled CLI, Capabilities, JSON Schema, and Desktop Integration away from v1 `accepted` / free-form `set-status` toward fingerprint-validated dismiss/undismiss and one common finding envelope (`evidence` as an array). Documented `site_scope_id`, append-only dismissal decisions, and classification-transition rules in the Findings contract.

**Documents:**
- `docs/CoreGuard Findings System.md` — added — formal Findings System contract (promoted from `.cursor/plans/CoreGuard-Findings-System.md`)
- `docs/CoreGuard CLI API.md` — updated — findings list/get/dismiss/undismiss; deferred Accepted and set-status for v1
- `docs/CoreGuard Capabilities.md` — updated — `findings.dismiss` / `findings.undismiss`; deferred `findings.set_status`
- `docs/CoreGuard JSON Schema.md` — updated — common public finding envelope; heuristic fields nested; status/classification enums
- `docs/CoreGuard Desktop Integration.md` — updated — dismiss/undismiss workflow; plugin authority wording
- `docs/README.md` — updated — Findings System ownership in source-of-truth table
- `.cursor/plans/CoreGuard-Findings-System.md` — updated — final clarifications; points at `docs/` as canonical

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
