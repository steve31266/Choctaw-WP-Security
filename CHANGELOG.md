# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **wp_users View activity** now opens a three-tab forensic panel:
  - **Database Activity** — existing posts/revisions/uploads/comments timeline
  - **Usermeta Table** — all paired `*usermeta` rows for the selected user (`ID`, `Meta Key`, `Meta Value`)
  - **File Activity** — greps WordPress root files, `wp-admin`, `wp-includes`, plugins, themes, and mu-plugins for the user's login and email (`Path`, `Filename`, `Line Number`, `Match`, `Contents`)

## [1.9.1] - 2026-07-07

### Changed

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
