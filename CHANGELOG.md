# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/steve31266/Choctaw-WP-Security/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/steve31266/Choctaw-WP-Security/releases/tag/v1.0.0
