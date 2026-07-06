# Choctaw WP Security

A lightweight WordPress security plugin that hardens common attack paths:

1. **XML-RPC abuse** — blocks unauthorized XML-RPC access
2. **Login brute force** — rate-limits failed `wp-login.php` attempts
3. **Uploads PHP execution** — blocks PHP in `wp-content/uploads` where the server allows it
4. **Exposed folders** — scans plugin and theme folders for missing directory index files
5. **Database scan** — inspects the `wp_options` table for potentially compromised records

Built for standard WordPress installs. No Composer, build tools, or external dependencies.

## Features

### XML-RPC Protection

- Returns HTTP **403** with plain text: `XML-RPC is disabled.`
- Blocks `xmlrpc.php` as early as possible during plugin load
- Disables XML-RPC via WordPress filters
- Removes the `X-Pingback` header
- Disables all XML-RPC methods
- Can be toggled on/off in settings
- Does **not** affect the WordPress REST API

### Login Rate Limiting

- Tracks failed login attempts using WordPress transients (no custom database tables)
- **Dual-scope tracking:**
  - **IP + username** — reduces collateral lockouts for repeated attempts against one account
  - **IP only** — stops username spraying from the same source IP
- Intercepts locked-out login attempts before the full authentication pipeline runs
- Shows a styled lockout notice on the login screen (not a generic server error)
- Generic public message only (no user enumeration):

  > Too many failed login attempts. Please try again later.

- Recent lockout log in admin (last 20 events)
- Does **not** permanently ban IPs or log passwords

### WP Core Verify-Checksums

- Manual **Scan Now** action on the settings page (does not run automatically)
- Uses WordPress's `get_core_checksums()` API for the installed version and locale
- Reports modified core files, missing core files, and unknown files in core-owned directories
- Detection-only: does not repair, delete, quarantine, or modify files
- Does **not** scan plugins, themes, uploads, mu-plugins, or `wp-config.php`

### Exposed Folders

- Manual **Scan Now** action on the settings page
- Scans one level down from `wp-content/plugins/` and `wp-content/themes/` for folders missing `index.php`, `index.html`, or `index.htm`
- Reports potentially exposed folders grouped by plugins and themes
- Provides Apache/LiteSpeed, Nginx, and folder-level remediation guidance
- Detection-only: does not add files, edit `.htaccess`, or change server configuration

### Database Scan

- Manual **Scan Now** action on the **Database Scan** admin tab
- Discovers all `*options` tables in the database and lets you choose which one to scan
- Shows table metadata (row count, data size, `siteurl`/`home` hosts, last updated) to help identify the correct table after staging copies or migrations
- Marks the WordPress configured table and tables whose URLs match the current site
- Warns when the configured table URL does not match the site but another discovered table does
- Reports potentially compromised or malicious records for investigation
- Checks site URL and security settings, active plugin consistency, cron events, large autoload options, PHP/execution patterns, known-malware option names, and scripts outside widget/theme options
- Establishes a per-table baseline on the first scan of each selected table and reports new/changed/removed options on subsequent scans of that same table
- Includes **Reset Baseline** to snapshot the current selected options table after cleanup
- Detection-only: does not delete, edit, or quarantine database rows

## Requirements

- WordPress **5.8+**
- PHP **7.4+**

## Installation

1. Copy the `choctaw-wp-security` folder from this repository into your WordPress plugins directory:

   ```
   wp-content/plugins/choctaw-wp-security/
   ```

   Or clone this repository and copy the `choctaw-wp-security` folder to that location.

2. In WordPress admin, go to **Plugins** and activate **Choctaw WP Security**.

3. Configure settings at **Settings → Choctaw WP Security**.

### Updating

Replace the plugin folder on the server with the latest version, then verify settings in admin. No build step is required.

If you previously used a standalone **Disable XML-RPC** plugin, deactivate and remove it after confirming XML-RPC blocking is enabled in Choctaw WP Security.

## Configuration

Default settings (recommended for most sites):

| Setting | Default |
|---|---|
| XML-RPC blocking | Enabled |
| Login rate limiting | Enabled |
| Allowed failed attempts | 5 |
| Failure window | 15 minutes |
| Lockout duration | 30 minutes |

### Admin page

The settings page under **Settings → Choctaw WP Security** includes:

- Feature toggles for XML-RPC blocking and login rate limiting
- Rate limit policy fields (attempts, window, lockout duration)
- Read-only status section showing feature state, current policy, and plugin version
- **Exposed Folders** — manual scan that identifies top-level plugin and theme folders missing common directory index files
- **WP Core Verify-Checksums** — manual scan that compares installed WordPress core files against official WordPress.org checksums for the current version and locale
- **Database Scan** — manual scan of a selected WordPress options table for potentially compromised records
- Recent lockout log with timestamp, IP address, attempted username, scope, and lockout duration

## How It Works

### XML-RPC

When enabled, direct requests to `xmlrpc.php` receive an early 403 response. Additional WordPress filters disable XML-RPC functionality site-wide. REST API endpoints such as `/wp-json/` are not affected.

### Login rate limiting

1. Each failed login increments both the IP-only and IP+username failure counters.
2. When either counter reaches the configured threshold within the failure window, a temporary lockout is created.
3. Further login attempts during the lockout are blocked and the user sees the styled lockout notice.
4. On successful login, the IP+username failure counter is cleared.
5. The IP-only failure counter is **not** cleared on successful login, which prevents an attacker with one valid account from resetting IP-wide spray protection.
6. Lockouts expire automatically after the configured duration.

### IP detection

The plugin uses `$_SERVER['REMOTE_ADDR']` by default and validates the address with `filter_var()`. It does **not** trust `X-Forwarded-For` by default. Trusted reverse-proxy support (for example Cloudflare) can be added later with explicit configuration.

### Transient records

This plugin uses WordPress transients for temporary state. It does **not** create custom database tables for rate limiting or scan results. In `wp_options`, each transient normally appears as two rows: `_transient_{key}` (the value) and `_transient_timeout_{key}` (the expiration timestamp). Plugin transients use keys prefixed with `cws_`.

| Purpose | Key pattern | Default TTL |
|---|---|---|
| Failed login count (per IP) | `cws_fail_ip_{hash}` | Failure window (15 minutes) |
| Lockout (per IP) | `cws_lock_ip_{hash}` | Lockout duration (30 minutes) |
| Failed login count (per IP + username) | `cws_fail_ipu_{hash}` | Failure window (15 minutes) |
| Lockout (per IP + username) | `cws_lock_ipu_{hash}` | Lockout duration (30 minutes) |
| Core checksum scan result | `cws_core_checksum_{user_id}` | 1 minute |
| Exposed folders scan result | `cws_exposed_folders_{user_id}` | 1 minute |
| Database scan result | `cws_database_scan_{user_id}` | 1 minute |

**Are they safe to keep?** Yes. These rows hold short-lived operational data such as failure counts, lockout flags, and scan results. They do not store passwords or other secrets. Active and recently expired rows are normal.

**Do they get removed?** Yes, primarily by expiration. Lockouts and failure counters expire after the configured window or duration. Scan results expire after one minute. WordPress removes expired transients when they are accessed and also during scheduled cleanup, so expired rows may remain visible in `wp_options` for a while before cleanup runs. On successful login, the plugin explicitly clears the IP+username failure counter only; the IP-only counter is intentionally left in place. There is no uninstall hook that deletes plugin transients; they are expected to age out on their own.

**Does repeated use create more records?** Admin scans reuse a fixed key per admin user, so running a scan again overwrites the previous result instead of adding rows. Login rate limiting reuses the same keys for a given IP or IP+username pair. The main scenario that temporarily increases row count is sustained failed login attempts from many different IP addresses, such as bot traffic. Those rows should drop off as TTLs expire and WordPress cleanup runs.

The plugin also stores regular (non-transient) options: `choctaw_wp_security_options` (settings), `choctaw_wp_security_lockout_log` (the last 20 lockout events shown in admin), and `choctaw_wp_security_options_baseline` (database scan change-tracking snapshot).

Sites with a persistent object cache (Redis, Memcached, etc.) may store transients in the cache backend instead of `wp_options`.

## Security Notes

**What this plugin does:**

- Blocks a common XML-RPC attack surface
- Slows brute-force and username-spraying attacks against `wp-login.php`
- Uses temporary transients instead of permanent IP bans
- Returns generic error messages to avoid user enumeration

**What this plugin does not do:**

- Block REST API access
- Block wp-admin globally
- Add CAPTCHA or two-factor authentication
- Act as a full web application firewall
- Stop distributed attacks from many different IP addresses
- Automatically edit third-party plugin or theme folders when exposed folders are found

**Known limitations:**

- Users behind shared IPs (NAT, office networks) may be briefly affected by IP-only lockouts
- Sites behind reverse proxies or CDNs may rate-limit by proxy IP unless trusted-proxy support is configured
- Custom login forms that bypass standard WordPress login hooks may not be protected

## Testing Checklist

After install or update, verify:

- [ ] Plugin activates without PHP errors
- [ ] Normal successful login works when not locked out
- [ ] Failed logins are counted
- [ ] After 5 failures within 15 minutes, login is blocked with the styled lockout notice
- [ ] Lockout message is generic and does not reveal whether a username exists
- [ ] Successful login clears IP+username failures but not the IP-only counter
- [ ] `POST` to `/xmlrpc.php` returns 403 with `XML-RPC is disabled.`
- [ ] REST API (`/wp-json/`) still works
- [ ] Settings save and persist correctly
- [ ] Exposed Folders scan runs manually and reports top-level plugin/theme folders missing common index files
- [ ] Database Scan discovers multiple options tables when present and scans the selected table
- [ ] Disabling XML-RPC blocking from settings stops XML-RPC blocking through this plugin
- [ ] Disabling login rate limiting from settings stops login blocking through this plugin

## Repository Layout

This repository contains a standalone WordPress plugin. It is not a full WordPress installation.

The plugin source lives in the `choctaw-wp-security/` folder at the repository root. Copy that folder into your site:

```
wp-content/plugins/choctaw-wp-security/
```

## Project Structure

```
choctaw-wp-security/
├── choctaw-wp-security.php          # Bootstrap, constants, activation hook
├── assets/css/
│   ├── login-lockout.css            # Login lockout styling
│   └── admin-core-checksum.css      # Core checksum scan results styling
└── includes/
    ├── class-plugin.php             # Module coordinator
    ├── class-utils.php              # Options, IP helper, transient keys
    ├── class-settings.php           # Admin settings page
    ├── class-core-checksum-scanner.php # WordPress core checksum scanner
    ├── class-options-scan-patterns.php # Database scan patterns and thresholds
    ├── class-options-table-discovery.php # Options table discovery and metadata
    ├── class-options-table-scanner.php # wp_options database scanner
    ├── class-xml-rpc-protection.php # XML-RPC blocking
    └── class-login-rate-limiter.php # Login rate limiting
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full release history.

### 1.4.2

- Paginated report tables (20 per page) across Database Scan, Verify Checksums, Exposed Folders, and Files Changes/Uploads
- Fixed Database Scan table selection not being submitted with Scan Now

### 1.4.1

- Database Scan can discover multiple options tables and lets you choose which one to scan

### 1.4.0

- Added Database Scan admin tab for the `wp_options` table with baseline change tracking

### 1.3.0

- Added Exposed Folders admin scan for top-level plugin and theme folders missing directory index files

### 1.2.1

- Added tabbed settings page sections, About This Plugin information, and a Plugins screen Settings link

### 1.2.0

- Added WP Core Verify-Checksums admin scan for modified, missing, and unknown WordPress core files

### 1.1.0

- Added uploads PHP lockdown with server-aware `.htaccess` management and Nginx guidance
- Added admin panels for recent core file changes and PHP files in uploads/mu-plugins
- Updated plugin description

### 1.0.1

- Improved lockout UX with styled login notice and early request intercept
- Fixed server 500 errors on some hosts when lockout was triggered

### 1.0.0

- Initial release: XML-RPC protection and dual-scope login rate limiting

## License

GPL-3.0-or-later

## Author

Choctaw Websites
