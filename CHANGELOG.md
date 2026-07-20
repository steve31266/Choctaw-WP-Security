# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.9.3] - 2026-07-19

### Added

- **Sassh Findings System (Phase 1/2):** network-wide persistence tables (`{base_prefix}sassh_scanner_executions`, `sassh_findings`, `sassh_dismissal_decisions`, `sassh_finding_events`), provisional `sassh_installation_id`, shared `Sassh_Findings_Service` (begin → record → finalize-with-absence, fingerprint-gated dismiss/undismiss, related findings query), and Uploads Folder as the first Findings producer (`php-file-in-uploads` → **Warning** + Needs Review).
- Centralized **Sassh authorization** (`Sassh_Capabilities`): single-site `manage_options`; Multisite `manage_network_options` (Super Admins); nonces on state-changing Findings admin actions. AJAX: `sassh_finding_dismiss` / `sassh_finding_undismiss`.

### Changed

- **Public product name** is **Sassh Security** (Site Audit over SSH): main bootstrap `sassh.php`, admin menu **Sassh Security**, page slugs `sassh*`, header uses `sassh-logo.png`. Text Domain, option keys, AJAX actions, and PHP class names unchanged.
- **Uploads Folder** no longer uses the prototype `Finding_Status_Store`; Clear History removed on that tab; status chrome label **Review Not Needed** (was “No Action Needed”).
- **Admin navigation** is a single WordPress menu item (**Sassh Security**). Home, Settings, About, and grouped Scans tabs live in an in-plugin sidebar on desktop; below 1100px a **Menu** hamburger opens the same navigation as a slide-over drawer.
- **Report tables** on viewports below 1100px use horizontal scrolling (min-width preserved) and slightly smaller type for emergency mobile/tablet viewing.

## [1.9.2] - 2026-07-16

### Changed

- **Vulnerabilities** scan now includes inactive themes and inactive plugins (in addition to core, active theme, and active plugins). Report order: WordPress Core, Active Theme, Inactive Themes, Active Plugins, Inactive Plugins, Unrecognized Components.
- **Vulnerabilities** Active Theme now resolves parent themes when a child theme is selected (parent reported as active for CVE scanning; child remains listed under Unrecognized Components when the API has no record).
- **Unrecognized Components** migrated to the standard report architecture (Risk, Status, Category, Name, State, Action with eye-expand Info/Contents | Why/How, dismiss controls, Name search, Status filter, Clear History).
- **Directory Browsing** migrated to the standard report architecture (Risk, Status, Path, Directory Browsing Blocked/Not Blocked/Unknown, eye-expand Info/Contents | Why/How, dismiss controls, AJAX Scan Now). Findings cover site-root `.htaccess` (Apache/LiteSpeed always; Nginx only when present as Info) plus HTTP tests of the `wp-content/plugins`, `themes`, and `uploads` roots.
- Finding **Status** now includes **No Action Needed** (auto-assigned when Risk is Safe). Needs Review remains for Critical/Review/Info and other non-Safe open items; Dismissed is unchanged.

### Added

- **Exposed Files** Scans tab (immediately after File Changes) that non-recursively scans the WordPress document root for sensitive leftover files (wp-config backups, `.env*`, SQL dumps, backup archives, diagnostic PHP, logs, Composer/npm metadata, `.git`/`.svn`). Report columns: Risk, Category, Filename, Actions; eye expand shows Info (Modified Date/Time, File Size, Permissions, Owner) + Contents (first 16K) | Why / How guidance, plus a **Key to Categories** Info Box.
- **Uploads Folder** and **MU-Plugins** Scans tabs (split from the former Files Changes/Uploads combined report), each with Scan Now, Risk/Category filters, and redesigned eye-expand panels.
- **Uploads Folder** findings use Risk=Critical and Category=PHP Executable; expand shows Last Modified, File Size, and the first 16K of file contents plus Why / How guidance.
- **MU-Plugins** findings use Risk=Alert and Category=MU-Plugin; expand shows plugin headers (Version, Author, Plugin URI, Update URI, Description), file size, last modified, and SHA-256 hash plus Why / How guidance.
- Shared report Risk styling (`admin-report-risk.css`) with standard colors: Critical (red), Suspicious/Alert/Missing (yellow), Warning (dark amber), Safe (green), Info/Review/N/A (gray); zebra striping that ignores expand rows; nested eye-expand child panels (border, radius, left accent). Risk filter uses Needs review / All risks (no separate recognized/safe checkbox).
- Unified **wp_options** findings table at 960px: Risk, Category, Option ID, Option, Actions; eye expand uses two columns — Info (Size, Detail) + Option Value | Why you are seeing this + How to proceed (preliminary copy varies by category and risk).
- Unified **wp_posts** findings table at 960px: Risk, Category, Post ID, Title, Type, Actions; eye expand uses two columns — Info (User ID, User Display Name, Status, Size, Detail) + Matched Snippet | Why you are seeing this + How to proceed (preliminary copy varies by category and risk).
- **WP-Cron** compact table (Risk, Category, Hook, Actions) at 960px width; eye expand uses two columns — Info (Schedule, Next Run, Source, Size, Details) + Raw Arguments | Summary + Recommendation.
- **Recent File Changes** Risk column (Safe/Critical/Missing/N/A) with eye expand (Risk explanation | Why this matters); always shows the fixed core-file watchlist (optional Risk filter only).
- Unified **Verify Checksums** table (Modified / Missing / Not Part of Core) with Risk/Category filters and eye expand; per-category Guidance Boxes removed.
- **Recent Lockouts** Risk=Info column with sortable headers (Time descending default).
- **wp_users** User Status filter, eye-icon activity expand, far-right pagination chrome.

### Changed

- Renamed the Scans tab **Files Changes/Uploads** to **File Changes** (Recent File Changes only) and ordered tabs: File Changes, Exposed Files, Uploads Folder, MU-Plugins, then the remaining existing tabs.
- Moved CoreGuard from **Settings → CoreGuard** to a top-level admin menu with **Home**, **Settings**, **Scans**, and **About** submenus (menu icon `coreguard-20.svg` via base64 data URI so WordPress can recolor it like Dashicons). Scan tools remain tabbed under **Scans**; Home, Settings, and About render without the scan tab bar.
- Branded **Scans** tab bar: light blue inactive tabs (`#eaf0f9`), dark blue active tab (`#0a3a7e`) with white text, top-only radius, bottom rule, and Dashicons per scan.
- Risk badges in scan reports use the CoreGuard SVG mark (with `currentColor`) instead of the Dashicons shield.
- wp_options and wp_posts scans map legacy Severity to Risk (`warning` → Suspicious); small autoload inventory maps to Safe.
- Shorter row excerpts on options/posts scans; detail panels carry the longer value/snippet.

### Removed

- Combined **PHP Files in Uploads and Must-Use Plugins** report (replaced by separate Uploads Folder and MU-Plugins tabs).
- **Plugins Found Inside Uploads Folder** report (security concern covered by PHP Files in Uploads).

### Added

- **WordPress Tables** on the Settings tab — discovers leftover table prefixes in the connected database, defaults to the live `$wpdb->prefix`, and allows an admin override when migration leftovers exist.
- Home Status row for **WordPress Tables** showing the selected prefix plus Auto/Override.

- **WP-Cron** admin tab — security-focused review of WP-Cron events moved out of wp_options.
  - Fact-only scanner with weighted scoring: Detection Rules → Score → Confidence → **Risk**
  - Default Risk filter is **Needs review** (non-recognized events); **All Risk** / Info include recognized maintenance jobs (no separate checkbox)
  - Recognized-only events report High / Very High confidence (certainty of classification); High and Very High confidence render in green
  - Multi-category pills, Risk/Category/Source filters, search, sortable columns, and eye-icon detail panels (Summary / Recommendation / Raw Arguments)
  - Gray **Key to Categories** Info Box and blue **How to Remove a WP-Cron Event** Guidance Box
  - Detection-only: does not delete or repair cron events
  - Recognized Core classification uses the core cron allowlist (including `wp_update_user_counts`) plus callbacks resolving under `wp-includes` / `wp-admin/includes`
  - Recognized Core hooks are not flagged as Unregistered Handler / Missing Source (handlers may only load during wp-cron execution)
  - Recognized Core hooks are not flagged as Duplicate Task based on hook name alone; only identical hook + args hashes count
  - Recommendation panel now shows one focused primary tip (plus at most one secondary for higher-risk findings) instead of stacked generic advice
  - Admin tab label and page heading use **WP-Cron** (internal keys remain `scheduled-tasks`)
  - Tab order places **WP-Cron** immediately before **wp_options**

### Changed

- Renamed the public product identity to **CoreGuard** (plugin folder/slug `coreguard`, Settings menu title, About copy, uploads `.htaccess` markers). Internal class names, option keys, AJAX actions, text domain, and `cws_*` prefixes are unchanged. Author is now Sashtastic, LLC. GitHub repository URL unchanged.
- Removed the Cron Events inventory section from the **wp_options** scan (use the **WP-Cron** tab). Stored wp_options reports drop the obsolete `cron_events` section on load so stale caches no longer show it.
- WP-Cron, wp_options, wp_posts, and wp_users no longer ask for a table on each scan; they use the shared WordPress Tables prefix from Settings.
- Settings form sanitization now preserves non-Settings option keys when saving.
- Split the former **Security Features** Settings group into two left-aligned sections: **Disable XML-RPC** and **Disable PHP Execution in Uploads**.
- **Disable XML-RPC** — section intro with **Why this matters**, indented **Block XML-RPC requests** checkbox, and live green/red **Active (Automatic)** / **Disabled (at Risk)** status banner.
- **Disable PHP Execution in Uploads** Settings UI is now explicitly three-way by detected server type:
  - **Apache / LiteSpeed** — feature summary, live **Active (Automatic)** / **Disabled (at Risk)** status banner, and **Enable protection (Recommended)** checkbox that manages uploads `.htaccess`
  - **Nginx** — **Manual configuration required** banner (no checkbox), explanation, and **Display Nginx code snippet** disclosure that expands a Guidance Box
  - **Unknown** — **Server type could not be confirmed** banner, dual-path guidance, interactive checkbox for `.htaccess` attempts, and the same Nginx snippet disclosure

## [1.9.1] - 2026-07-09

### Added

- **Home** admin tab — default landing tab with the Status section and Recent Lockouts log.
- **wp_users View activity** now opens a three-tab forensic panel:
  - **Database Activity** — existing posts/revisions/uploads/comments timeline
  - **Usermeta Table** — all paired `*usermeta` rows for the selected user (`ID`, `Meta Key`, `Meta Value`)
  - **File Activity** — greps WordPress root files, `wp-admin`, `wp-includes`, plugins, themes, and mu-plugins for the user's login and email (`Path`, `Filename`, `Line Number`, `Match`, `Contents`)

### Changed

- Renamed the **Main** admin tab label to **Settings** (internal slug `main` unchanged for URL compatibility).
- Moved Status and Recent Lockouts from Settings onto the new Home tab.
- **About This Plugin** tab — added an **Important: Please Read First!** section explaining the plugin's active-administration intent, with a bulleted list of recommended security practices; reorganized attribution under a **Credits** heading.
- Reduced the About tab Choctaw Websites logo size by 25%.

## [1.9.0] - 2026-07-07

### Added

- **Block Username Discovery** on the Main tab — four independently toggled protections (all enabled by default):
  - Block Anonymous Access to User REST API (`/wp/v2/users` routes for anonymous visitors)
  - Block Anonymous Access to User Enumeration (`/?author={id}` for anonymous visitors)
  - Block Anonymous Access to Author Archive pages (`/author/{nicename}/` for anonymous visitors)
  - Normalize failed login error message to `Failed login, please try again.`

## [1.8.1] - 2026-07-06

### Changed

- **Verify Checksums** report now shows three separate sections (Modified, Missing, Unknown). Empty sections display "No files reported." Sections with findings list affected files first, followed by category-specific remediation steps.

## [1.8.0] - 2026-07-06

### Added

- **Vulnerabilities** admin tab — queries the public WPVulnerability API for known vulnerabilities in WordPress core, the active theme, and active plugins.
- Four report sections: WordPress Core, Active Theme, Active Plugins, and Unrecognized Components (all installed plugins/themes with no API record).
- Expandable green/red `<details>` rows per scanned component with inline vulnerability name, description, severity, CWE, version range, and external reference links.
- Per-slug API response caching in transients (`cws_wpv_*`) for 12 hours.
- WPVulnerability attribution on the Vulnerabilities tab and in About This Plugin.

## [1.7.0] - 2026-07-06

### Added

- **wp_posts** admin tab — scans a selected `*posts` table for potentially malicious content.
- Six report sections: PHP & Execution Patterns, Script & Iframe Injection, High-Confidence Script Patterns, SEO Spam Titles, Large Post Content, and Changed Posts Since Last Scan (baseline diff).
- Multi-table support — when more than one `*posts` table exists, choose which table to scan (same pattern as wp_options).
- User ID column displays `post_author` with the author's display name shown on hover (resolved from the paired `*users` table).
- AJAX/JSON report interface with client-side pagination, sortable columns, and Reset Baseline.

## [1.6.0] - 2026-07-06

### Added

- **wp_users** admin tab — lists all users from a selected `*users` table with sortable columns and pagination (20 per page).
- Per-user **View activity** drill-down — lazy-loaded forensic report of detectable actions (created/edited content, uploads, comments).
- Multi-table support for users — when more than one `*users` table exists, choose which table to load (same pattern as wp_options).

### Changed

- Renamed the **Database Scan** admin tab label to **wp_options** (internal slug `database-scan` unchanged for URL compatibility).

## [1.5.2] - 2026-07-06

### Added

- Database Scan now flags `phar://` in PHP & Execution Patterns and in Cron Events suspicious payload checks.

## [1.5.1] - 2026-07-06

### Changed

- Database Scan Cron Events now reports a classified inventory of stored cron jobs.
  - Cron rows are labeled as **WP Core**, **Plugin/Theme**, **Investigate**, or **Suspicious**.
  - Known WordPress core hooks such as `wp_delete_temp_updater_backups` are identified as core instead of reported as unknown-handler warnings.
  - Each cron event still reports the `option_id` for the underlying `cron` option row to make database lookup faster.

## [1.5.0] - 2026-07-06

### Added

- Database Scan now uses an AJAX/JSON report interface.
  - Scans and baseline resets run without a full page reload.
  - Report pagination happens client-side without adding page parameters to the URL.
  - Database Scan report column headings are sortable across the full section dataset.
  - Default sort indicators are shown immediately, with Large Autoload Options defaulting to Size descending.
  - A bottom **Rescan Selected Table** button appears after the report for long cleanup/review sessions.

## [1.4.2] - 2026-07-06

### Added

- Paginated report tables (20 records per page) with navigation links when a section has more results.
  - Applies to Database Scan sections, Verify Checksums, Exposed Folders, and Files Changes/Uploads.
  - Large Autoload and pattern-matching scans now collect full result sets for pagination.

### Fixed

- Database Scan table picker now submits the selected options table reliably when clicking **Scan Now** or **Reset Baseline**.

## [1.4.1] - 2026-07-06

### Added

- Database Scan now discovers all `*options` tables in the database and lets you choose which table to scan.
  - Shows row count, data size, `siteurl`/`home` hosts, and last-updated metadata to help identify the correct table.
  - Marks the WordPress configured table and tables whose URLs match the current site.
  - Warns when the configured table URL does not match the site but another discovered table does.
  - Baseline snapshots are scoped per selected table; switching tables establishes a new baseline.

## [1.4.0] - 2026-07-06

### Added

- Added a **Database Scan** admin tab that inspects the WordPress `wp_options` table for potentially compromised records.
  - Manual **Scan Now** action with detection-only reporting (no automatic fixes).
  - Checks site URL and security settings, active plugin consistency, cron events, large autoload options, PHP/execution patterns, known-malware option names, and scripts outside widget/theme options.
  - Establishes a `wp_options` baseline on the first scan and reports new/changed/removed options on subsequent scans.
  - Includes a **Reset Baseline** action to snapshot the current options table after cleanup.

## [1.3.0] - 2026-07-05

### Added

- Added an **Exposed Folders** admin scan for top-level plugin and theme directories missing common directory index files.
  - Scans one level down from `wp-content/plugins/` and `wp-content/themes/` only after a manual **Scan Now** action.
  - Reports potentially exposed folders grouped by plugins and themes.
  - Provides Apache/LiteSpeed, Nginx, and folder-level remediation guidance.
  - Detection-only: does not add files, edit `.htaccess`, or change server configuration.

## [1.2.1] - 2026-07-05

### Added

- Added WordPress-style admin tabs to organize the settings page into **Main**, **Files Changes/Uploads**, **Verify Checksums**, and **About This Plugin** sections.
- Added an **About This Plugin** tab with free-use information, official GitHub repository link, Choctaw Websites attribution, and Choctaw Websites branding.
- Added a **Settings** plugin action link from the Plugins screen to the Choctaw WP Security settings page.

### Changed

- Moved existing file-change/upload reports and checksum scanning into their own tabs for a cleaner admin layout.

## [1.2.0] - 2026-07-05

### Added

- **WP Core Verify-Checksums** admin scan on the settings page.
  - Compares installed WordPress core files against official WordPress.org checksums for the current version and locale using `get_core_checksums()`.
  - Reports modified files, missing files, and unknown files in core-owned areas (`ABSPATH` root core files, `wp-admin/`, and `wp-includes/`).
  - Excludes site-specific paths such as `wp-config.php`, `wp-content/`, `.htaccess`, and common local root files from false-positive reporting.
  - Caps displayed unknown files at 50 and notes when additional unknown files were found.
  - Detection-only: does not repair, delete, quarantine, or modify files.
  - Includes timeout protection and grouped result output on manual **Scan Now** action.

## [1.1.0] - 2026-07-05

### Added

- **Uploads PHP lockdown** — optional security feature (enabled by default) to block PHP execution in `wp-content/uploads`.
  - On Apache, LiteSpeed, and OpenLiteSpeed, the plugin manages a marker block in `wp-content/uploads/.htaccess`.
  - On Nginx, the plugin shows a copyable server configuration snippet and reports that manual setup is required.
  - On unknown servers, the plugin attempts `.htaccess` enforcement when the uploads directory is writable and reports whether the managed block was installed.
- **Server-aware enforcement status** on the settings page, including labels such as *Protected by managed .htaccess block*, *Manual Nginx configuration required*, and *Unable to write uploads .htaccess*.
- **Recent File Changes** panel listing last-modified times for stable WordPress core and configuration files commonly targeted during compromises.
- **PHP Files in Uploads and Must-Use Plugins** panel to surface suspicious PHP files in `wp-content/uploads` and `wp-content/mu-plugins`.

### Changed

- Plugin description updated to reflect XML-RPC protection, login rate limiting, and uploads PHP lockdown.

## [1.0.1] - 2026-07-05

### Fixed

- Improved lockout UX with styled login notice and early request intercept.
- Fixed server 500 errors on some hosts when lockout was triggered.

## [1.0.0] - 2026-07-05

### Added

- Initial release: XML-RPC protection and dual-scope login rate limiting.
- Admin settings page with feature toggles, rate limit policy, and recent lockout log.

[1.5.2]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.4.2...v1.5.0
[1.4.2]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/steve31266/Choctaw-WP-Security/releases/tag/v1.0.0
