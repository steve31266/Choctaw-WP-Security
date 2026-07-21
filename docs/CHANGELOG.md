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

## 2026-07-20 20:45 CDT

**Summary:** Locked and shipped Findings Phase **3.4.5** (object-level Findings): Finding identity excludes `rule_id`; first-class `sassh_finding_categories`; directional dismissal + carry-forward; success-only negative reconcile with incomplete-run strengthening; structured guidance composer + subset recipes; schema v2 reset. Supersedes rule-identity assumptions from Phases 1–3.4 (including Phase 3.4 Q1 A).

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §3.11 / §5.2 / §5.7 / §18 Phase 3.4.5
- `.cursor/plans/findings_phase_3_4_5_grouped_report.plan.md` — updated — approved + implemented
- `.cursor/plans/findings_phase_3x_index.plan.md` — updated — 3.4.5 status
- Historical phase plans 1/2–3.4 — supersession notices
- `CHANGELOG.md` — updated — `[1.9.3.5]`
- `docs/README.md` — updated — Findings status through Phase 3.4.5
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.5`

## 2026-07-20 18:40 CDT

**Summary:** Locked and shipped Findings Phase **3.4** (WP-Cron / Scheduled Tasks → Sassh Findings): registered `object_type=cron_event`; registered-site `blog_id` gate; per problem-rule Findings after aggregation; recognized-only report inventory; rule-based risk; Clear History removed; fresh start; capped/sanitized argument previews.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §5 / §11 / §18 Phase 3.4 complete; next = 3.5
- `.cursor/plans/CoreGuard-Findings-System.md` — align with formal PRD (working copy)
- `.cursor/plans/findings_phase_3_4_wp_cron.plan.md` — updated — approved + implemented
- `.cursor/plans/findings_phase_3x_index.plan.md` — updated — 3.4 complete
- `CHANGELOG.md` — updated — `[1.9.3.4] - 2026-07-20`
- `docs/README.md` — updated — Findings status through Phase 3.4
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.4`

## 2026-07-20 12:50 CDT

**Summary:** Locked and shipped Findings Phase **3.3** (Database options → Sassh Findings): registered `object_type=option`; required registered-site `blog_id` (reject foreign/orphaned tables before begin; archived registered sites accepted); rule-based risk (no legacy warning→suspicious); PHP Critical only on strong combinations; ≥threshold autoload Findings only; Clear History + Reset Baseline removed; fresh start; dismiss cache rehydration.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §5 / §11 / §18 Phase 3.3 complete; next = 3.4
- `.cursor/plans/CoreGuard-Findings-System.md` — align with formal PRD (working copy)
- `.cursor/plans/findings_phase_3_3_database_options.plan.md` — updated — approved + implemented
- `.cursor/plans/findings_phase_3x_index.plan.md` — updated — 3.3 complete
- `CHANGELOG.md` — updated — `[1.9.3.3] - 2026-07-20`
- `docs/README.md` — updated — Findings status through Phase 3.3
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.3`

## 2026-07-20 00:20 CDT

**Summary:** Plugin version set to **1.9.3.2** for the Findings Phase 3.2 release (Exposed Files → Sassh Findings), including dismiss-status cache rehydration fix.

**Documents:**
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.2`
- `CHANGELOG.md` — updated — `[1.9.3.2] - 2026-07-20` release notes
- `README.md` — updated — 1.9.3.2 changelog summary

## 2026-07-19 23:50 CDT

**Summary:** Locked and shipped Findings Phase **3.2** (Exposed Files → Sassh Findings): kebab-case pattern `rule_id`s, canonical risk mapping (no `alert`; composer/package → Suspicious; `.git` → Info / Review Not Needed), directory sentinel `sha256:directory`, scope-bounded absence, AJAX/JS Findings parity with related-on-expand vs Verify Checksums, Clear History removed, fresh start.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §5.7 / §11 / §18 Phase 3.2 complete; next = 3.3
- `.cursor/plans/CoreGuard-Findings-System.md` — aligned with formal PRD
- `.cursor/plans/findings_phase_3_2_exposed_files.plan.md` — updated — approved + implemented
- `.cursor/plans/findings_phase_3x_index.plan.md` — updated — 3.2 complete
- `CHANGELOG.md` — updated — Unreleased Phase 3.2 notes
- `docs/README.md` — updated — Findings status through Phase 3.2

## 2026-07-19 23:30 CDT

**Summary:** Plugin version set to **1.9.3.1** for the Findings Phase 3.1 release (Verify Checksums → Sassh Findings), including post-QA Status/Path display fixes.

**Documents:**
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.1`
- `CHANGELOG.md` — updated — `[1.9.3.1] - 2026-07-19` release notes
- `README.md` — updated — 1.9.3.1 changelog summary

## 2026-07-19 23:15 CDT

**Summary:** Locked and shipped Findings Phase **3.1** (Verify Checksums → Sassh Findings): three `core-file-*` rules, incomplete-coverage reporting, requested vs effective checksum locales, missing-file reappearance → Needs Review, AJAX/JS report parity with Uploads/MU.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — §11 / §18 Phase 3.1 complete; next = 3.2
- `.cursor/plans/CoreGuard-Findings-System.md` — aligned with formal PRD
- `.cursor/plans/findings_phase_3_1_core_checksums.plan.md` — updated — implemented
- `.cursor/plans/findings_phase_3x_index.plan.md` — updated — 3.1 complete
- `CHANGELOG.md` — updated — Unreleased Phase 3.1 notes

## 2026-07-19 22:50 CDT

**Summary:** Added summary-only Findings Phase **3.1–3.8** plan documents (plus index) under `.cursor/plans/` for dedicated implementation chats; each references Phase 1/2, Phase 3.0, the formal PRD, and sibling 3.x plans.

**Documents:**
- `.cursor/plans/findings_phase_3x_index.plan.md` — added — Phase 3.x index
- `.cursor/plans/findings_phase_3_1_*.plan.md` … `findings_phase_3_8_*.plan.md` — added — per-phase summaries
- `docs/README.md` — updated — link to Phase 3.x index

## 2026-07-19 22:45 CDT

**Summary:** Plugin version set to **1.9.3.0** for the Findings Phase 3.0 release (four-part WordPress plugin version string).

**Documents:**
- `coreguard/sassh.php` — updated — `Version` / `CHOCTAW_WP_SECURITY_VERSION` → `1.9.3.0`
- `CHANGELOG.md` — updated — `[1.9.3.0] - 2026-07-19` release notes
- `README.md` — updated — 1.9.3.0 changelog summary

## 2026-07-19 22:40 CDT

**Summary:** Post–Phase 3.0 docs sync: renamed completed Phase 3 work to **Phase 3.0**; locked remaining Findings scanner migrations and closeout as Phase **3.1–3.8** (checksums → exposed files → options → cron → vulns → directory browsing → optional posts → store wind-down); next deliverable is the Phase 3.1 plan. Updated Multisite/related-findings wording to match shipped 3.0 behavior. Manual QA for 3.0 recorded as passed.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — status, §3.10, §5.7, §11, §18–§19 Phase 3.0 / 3.1–3.8
- `docs/README.md` — updated — Findings Phase 3.0 / 3.x status note
- `.cursor/plans/findings_phase_3_943aa5f0.plan.md` — updated — status complete/QA’d; follow-ons as 3.1–3.8
- `.cursor/plans/CoreGuard-Findings-System.md` — synced with formal PRD
- `README.md` — updated — Findings changelog blurb for Phase 3.0

## 2026-07-19 20:00 CDT

**Summary:** Locked and recorded Findings Phase 3 decisions: full Multisite Network Admin Sassh shell; required centralized auth on all Sassh AJAX; Multisite network-option settings fresh start (no site-option migration/fallback); MU-Plugins Findings migration (`suspicious`, `php-like-file-in-mu-plugins`, missing-dir empty success / overflow-only FILE_LIMIT incomplete); related-findings detail UI with fixture-based correlation acceptance.

**Documents:**
- `docs/CoreGuard Findings System.md` — updated — status, §18 Phase 3 complete, next deliverable
- `docs/README.md` — updated — Findings Phase 1–3 status note
- `.cursor/plans/findings_phase_3_943aa5f0.plan.md` — approved implementation plan
- `.cursor/plans/CoreGuard-Findings-System.md` — sync Phase 3 status with formal PRD

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
