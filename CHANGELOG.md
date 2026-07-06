# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.3.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/steve31266/Choctaw-WP-Security/releases/tag/v1.0.0
