# CoreGuard

A lightweight WordPress security plugin that hardens common attack paths:

1. **XML-RPC abuse** — blocks unauthorized XML-RPC access
2. **Login brute force** — rate-limits failed `wp-login.php` attempts
3. **Uploads PHP execution** — blocks PHP in `wp-content/uploads` where the server allows it
4. **Username discovery** — blocks common ways bots enumerate WordPress usernames
5. **Exposed folders** — scans plugin and theme folders for missing directory index files
6. **Verify Checksums** — compares WordPress core files against official WordPress.org checksums
7. **WP-Cron** — security-focused review of WP-Cron events stored in the `cron` option
8. **wp_options scan** — unified Risk/Category findings table for potentially compromised option records
9. **wp_posts scan** — unified Risk/Category findings table for potentially malicious post content
10. **wp_users review** — lists users from the `wp_users` table with per-user Database Activity, Usermeta, and File Activity drill-downs (eye expand)
11. **Vulnerabilities** — checks WordPress core, themes (active and inactive), and plugins (active and inactive) against the WPVulnerability API for known CVEs

Built for standard WordPress installs. No Composer, build tools, or bundled PHP dependencies. The Vulnerabilities scan requires outbound HTTPS access to `wpvulnerability.net`.

## Features

### XML-RPC Protection

- Returns HTTP **403** with plain text: `XML-RPC is disabled.`
- Blocks `xmlrpc.php` as early as possible during plugin load
- Disables XML-RPC via WordPress filters
- Removes the `X-Pingback` header
- Disables all XML-RPC methods
- Can be toggled on/off in settings
- Does **not** block anonymous access to the WordPress users REST endpoint when username discovery blocking is disabled

### Block Username Discovery

Four independently toggled protections on the **Settings** tab (all enabled by default):

- **Block Anonymous Access to User REST API** — returns HTTP **403** for anonymous requests to `/wp-json/wp/v2/users` and `/wp-json/wp/v2/users/{id}`
- **Block Anonymous Access to User Enumeration** — returns HTTP **403** for anonymous `/?author={id}` requests (uses the theme 403 template when available)
- **Block Anonymous Access to Author Archive pages** — returns HTTP **403** for anonymous `/author/{nicename}/` requests (uses the theme 403 template when available)
- **Normalize failed login error message** — replaces distinct WordPress login failure messages with: `Failed login, please try again.`

Logged-in users are not affected by the three anonymous blocking options. These settings address the most common username discovery vectors but do not block every possible method.

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

### Vulnerabilities

- Manual **Scan Now** action on the **Vulnerabilities** admin tab
- Queries the public [WPVulnerability](https://www.wpvulnerability.com/) API at `wpvulnerability.net` for known vulnerabilities
- Scans WordPress core, themes (active and inactive), and plugins (active and inactive) for API-recognized components
- Reports six sections: WordPress Core, Active Theme, Inactive Themes, Active Plugins, Inactive Plugins, and Unrecognized Components
- Expandable green/red rows per scanned component with inline vulnerability detail, severity, CWE, and external reference links
- Lists all installed plugins and themes not recognized by the API (active or inactive) in a standard report table (Risk, Status, Category, Name, State, Action) with eye-expand guidance and dismiss controls
- Per-slug API responses cached in transients for 12 hours during scans
- Credits WPVulnerability on the tab and in About This Plugin
- Detection-only: does not update, deactivate, or modify components
- Does **not** scan PHP, Apache, MySQL, or other hosting stack software

### Exposed Folders

- Manual **Scan Now** action on the settings page
- Scans one level down from `wp-content/plugins/` and `wp-content/themes/` for folders missing `index.php`, `index.html`, or `index.htm`
- Reports potentially exposed folders grouped by plugins and themes
- Provides Apache/LiteSpeed, Nginx, and folder-level remediation guidance
- Detection-only: does not add files, edit `.htaccess`, or change server configuration

### WP-Cron

- Manual **Scan Now** action on the **WP-Cron** admin tab
- Inspects WP-Cron events stored in the WordPress `cron` option (does not cover Action Scheduler or OS/server cron)
- Uses the WordPress Tables prefix from **Settings** (defaults to the live `$wpdb->prefix`)
- Fact-only detection engine: rules and signals → weighted score → confidence → **Risk** level
- Default Risk filter is **Needs review** (non-recognized events); choose **All Risk** or a specific level (including Info) to include recognized maintenance jobs
- Multi-category pills (Unknown Hook, Unregistered Handler, Unusual Frequency, Suspicious Arguments, and more)
- Compact findings table (Risk, Category, Hook, Actions) within the standard 960px report width
- Filterable by Risk, Category, and Source; searchable by hook or source; sortable columns with pagination
- Eye-icon expand: left Info panel (Schedule, Next Run, Source, Size, Details) + Raw Arguments; right Summary + Recommendation
- Key to Categories info box and How to Remove a WP-Cron Event guidance (WP-CLI / trusted plugins; no in-plugin deletion)
- Detection-only: does not delete, edit, or repair cron events

### wp_options

- Manual **Scan Now** action on the **wp_options** admin tab
- Uses the WordPress Tables prefix from **Settings** (defaults to the live WordPress-configured `*options` table)
- Reports potentially compromised or malicious records for investigation
- Checks site URL and security settings, active plugin consistency, large autoload options, PHP/execution patterns, known-malware option names, and scripts outside widget/theme options
- Displays scan reports through an AJAX/JSON interface with client-side pagination and sortable columns
- Establishes a per-table baseline on the first scan of each options table and reports new/changed/removed options on subsequent scans of that same table
- Includes **Reset Baseline** to snapshot the current options table after cleanup
- Detection-only: does not delete, edit, or quarantine database rows

### wp_posts

- Manual **Scan Now** action on the **wp_posts** admin tab
- Uses the WordPress Tables prefix from **Settings** (defaults to the live WordPress-configured `*posts` table)
- Reports potentially compromised or malicious post content for investigation
- Checks PHP and execution patterns, script and iframe injections, high-confidence script patterns, SEO spam titles, large post content, and baseline change tracking
- Resolves author display names from the paired `*users` table; shows **User ID** in the report with display name on hover
- Displays scan reports through an AJAX/JSON interface with client-side pagination and sortable columns
- Establishes a per-table baseline on the first scan of each posts table and reports new/changed/removed posts on subsequent scans
- Includes **Reset Baseline** to snapshot the current posts table after cleanup
- Detection-only: does not delete, edit, or quarantine database rows

### wp_users

- Manual **Load Users** action on the **wp_users** admin tab
- Uses the WordPress Tables prefix from **Settings** (defaults to the live WordPress-configured `*users` table)
- Lists every user with ID, login, email, registration date, role label, and display name
- Sortable columns and client-side pagination (20 per page) through an AJAX/JSON interface
- **View activity** on each user row opens a three-tab forensic panel on demand:
  - **Database Activity** — created or edited content, media uploads, and comments attributed to that user
  - **Usermeta Table** — all meta rows for that user from the paired `*usermeta` table
  - **File Activity** — greps WordPress root files, `wp-admin`, `wp-includes`, plugins, themes, and mu-plugins for the user's login and email (uploads excluded)
- Does **not** detect who created another user account or changed site settings — WordPress core does not record those actions with a user ID
- Read-only: does not modify users, usermeta, or files

## Requirements

- WordPress **5.8+**
- PHP **7.4+**

## Installation

1. Copy the `coreguard` folder from this repository into your WordPress plugins directory:

   ```
   wp-content/plugins/coreguard/
   ```

   Or clone this repository and copy the `coreguard` folder to that location.

2. In WordPress admin, go to **Plugins** and activate **CoreGuard**.

3. Configure settings at **CoreGuard → Settings**.

### Updating

Replace the plugin folder on the server with the latest version, then verify settings in admin. No build step is required.

If you previously used a standalone **Disable XML-RPC** plugin, deactivate and remove it after confirming XML-RPC blocking is enabled in CoreGuard.

## Configuration

Default settings (recommended for most sites):

| Setting | Default |
|---|---|
| XML-RPC blocking | Enabled |
| Login rate limiting | Enabled |
| Allowed failed attempts | 5 |
| Failure window | 15 minutes |
| Lockout duration | 30 minutes |

### Admin pages

CoreGuard appears as a top-level admin menu with four submenus:

- **Home** — read-only status section showing feature state, WordPress Tables prefix, current policy, and plugin version, plus the recent lockout log
- **Settings** — feature toggles for XML-RPC blocking, login rate limiting, uploads PHP lockdown, and username discovery; rate limit policy fields; **WordPress Tables** prefix picker for leftover staging/migration installs. Uploads PHP lockdown is server-aware: Apache/LiteSpeed shows an Active/Disabled status with automatic `.htaccess` protection; Nginx shows Manual configuration required with a disclosable config snippet; unknown servers show an unconfirmed-server banner while still offering the `.htaccess` checkbox and Nginx snippet.
- **Scans** — tabbed scan tools:
  - **File Changes** — recent high-value core file watchlist with checksum verification
  - **Uploads Folder** — Scan Now inventory of PHP executable files under uploads (Critical / PHP Executable)
  - **MU-Plugins** — Scan Now inventory of must-use plugin PHP files (Alert / MU-Plugin) with header metadata
  - **Directory Browsing** — Scan Now report for site-root `.htaccess` posture plus HTTP tests of the `plugins`, `themes`, and `uploads` folder roots (Risk / Status / Path / Blocked|Not Blocked|Unknown)
  - **Verify Checksums** — manual scan that compares installed WordPress core files against official WordPress.org checksums; findings are shown with Risk/Category filters and remediation guidance
  - **Vulnerabilities** — manual scan of WordPress core, themes (active and inactive), and plugins (active and inactive) against the WPVulnerability API
  - **WP-Cron** — security-focused WP-Cron review with risk scoring; recognized maintenance jobs hidden by default
  - **wp_options** — manual scan of the configured WordPress options table for potentially compromised records
  - **wp_posts** — manual scan of the configured WordPress posts table for potentially malicious content
  - **wp_users** — browse the configured WordPress users table with activity and usermeta helpers
- **About** — plugin purpose, usage guidance, and attribution

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
| Core checksum scan result | `cws_core_checksum_{user_id}` | 12 hours |
| Vulnerabilities scan result | `cws_component_scan_{user_id}` | 12 hours |
| Exposed folders scan result | `cws_exposed_folders_{user_id}` | 12 hours |
| Database scan result | `cws_database_scan_{user_id}` | 12 hours |
| Posts scan result | `cws_posts_scan_{user_id}` | 12 hours |
| Users table result | `cws_users_table_{user_id}` | 12 hours |

**Are they safe to keep?** Yes. These rows hold short-lived operational data such as failure counts, lockout flags, and scan results. They do not store passwords or other secrets. Active and recently expired rows are normal.

**Do they get removed?** Yes, primarily by expiration. Lockouts and failure counters expire after the configured window or duration. Scan results expire after 12 hours and are refreshed while viewing paginated reports. WordPress removes expired transients when they are accessed and also during scheduled cleanup, so expired rows may remain visible in `wp_options` for a while before cleanup runs. On successful login, the plugin explicitly clears the IP+username failure counter only; the IP-only counter is intentionally left in place. There is no uninstall hook that deletes plugin transients; they are expected to age out on their own.

**Does repeated use create more records?** Admin scans reuse a fixed key per admin user, so running a scan again overwrites the previous result instead of adding rows. Login rate limiting reuses the same keys for a given IP or IP+username pair. The main scenario that temporarily increases row count is sustained failed login attempts from many different IP addresses, such as bot traffic. Those rows should drop off as TTLs expire and WordPress cleanup runs.

The plugin also stores regular (non-transient) options: `choctaw_wp_security_options` (settings), `choctaw_wp_security_lockout_log` (the last 20 lockout events shown in admin), `choctaw_wp_security_options_baseline` (database scan change-tracking snapshot), and `choctaw_wp_security_posts_baseline` (posts scan change-tracking snapshot). Scan results are also backed up in user meta so report pagination can survive object-cache transient eviction.

Sites with a persistent object cache (Redis, Memcached, etc.) may store transients in the cache backend instead of `wp_options`.

## Security Notes

**What this plugin does:**

- Blocks a common XML-RPC attack surface
- Slows brute-force and username-spraying attacks against `wp-login.php`
- Blocks common anonymous username discovery vectors (REST users endpoint, author query, author archives)
- Uses temporary transients instead of permanent IP bans
- Returns generic error messages to avoid user enumeration

**What this plugin does not do:**

- Block all REST API access (only anonymous `/wp/v2/users` routes when enabled)
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
- [ ] Anonymous `GET /wp-json/wp/v2/users` returns 403 when username discovery blocking is enabled
- [ ] Anonymous `GET /wp-json/wp/v2/users/1` returns 403 when username discovery blocking is enabled
- [ ] Logged-in users can still access `/wp-json/wp/v2/users` when username discovery blocking is enabled
- [ ] Anonymous `GET /?author=1` returns 403 when user enumeration blocking is enabled
- [ ] Anonymous `GET /author/{nicename}/` returns 403 when author archive blocking is enabled
- [ ] Failed login shows `Failed login, please try again.` when login error normalization is enabled
- [ ] REST API (`/wp-json/`) still works for non-users routes
- [ ] Settings save and persist correctly
- [ ] CoreGuard → Settings → WordPress Tables shows the live prefix and is grayed out when only one prefix exists
- [ ] CoreGuard → Settings → WordPress Tables allows overriding the prefix when multiple leftover installs exist
- [ ] Home Status shows the WordPress Tables prefix with Auto or Override
- [ ] Exposed Folders scan runs manually and reports top-level plugin/theme folders missing common index files
- [ ] Vulnerabilities scan runs manually and reports core, active/inactive theme, and active/inactive plugin vulnerability status
- [ ] Vulnerabilities scan lists unrecognized installed plugins/themes in the Unrecognized Components section
- [ ] WP-Cron / wp_options / wp_posts / wp_users use the Settings prefix and no longer show per-tab table pickers
- [ ] wp_posts User ID hover shows display name from paired users table
- [ ] wp_users View activity Database Activity tab shows detectable content, upload, and comment activity for a user
- [ ] wp_users View activity Usermeta Table tab lists all meta rows for the selected user
- [ ] wp_users View activity File Activity tab finds login/email matches in code directories (including core files such as `wp-includes/functions.php`)
- [ ] Disabling XML-RPC blocking from settings stops XML-RPC blocking through this plugin
- [ ] Disabling login rate limiting from settings stops login blocking through this plugin

## Repository Layout

This repository contains a standalone WordPress plugin. It is not a full WordPress installation.

The plugin source lives in the `coreguard/` folder at the repository root. Copy that folder into your site:

```
wp-content/plugins/coreguard/
```

## Project Structure

```
coreguard/
├── coreguard.php          # Bootstrap, constants, activation hook
├── assets/
│   ├── css/
│   │   ├── login-lockout.css        # Login lockout styling
│   │   ├── admin-core-checksum.css  # Admin report styling
│   │   ├── admin-help.css           # Help panels, guidance/info boxes
│   │   └── admin-scheduled-tasks.css # WP-Cron report UI
│   └── js/
│       ├── admin-database-scan.js   # AJAX wp_options report UI
│       ├── admin-scheduled-tasks.js # AJAX WP-Cron report UI
│       ├── admin-posts-scan.js      # AJAX wp_posts report UI
│       └── admin-users-table.js     # AJAX wp_users report UI
└── includes/
    ├── class-plugin.php             # Module coordinator
    ├── class-utils.php              # Options, IP helper, transient keys
    ├── class-settings.php           # Admin settings page
    ├── class-core-checksum-scanner.php # WordPress core checksum scanner
    ├── class-component-vulnerability-scanner.php # WPVulnerability API component scanner
    ├── class-table-prefix-discovery.php # Shared WordPress table-prefix discovery
    ├── class-options-scan-patterns.php # Database scan patterns and thresholds
    ├── class-options-table-discovery.php # Options table discovery and metadata
    ├── class-options-table-scanner.php # wp_options database scanner
    ├── class-scheduled-tasks-patterns.php # WP-Cron detection weights and thresholds
    ├── class-scheduled-tasks-scanner.php # Fact-only WP-Cron scanner
    ├── class-scheduled-tasks-presenter.php # WP-Cron UI presentation layer
    ├── class-posts-scan-patterns.php # Posts scan patterns and thresholds
    ├── class-posts-table-discovery.php # Posts table discovery and metadata
    ├── class-posts-table-scanner.php # wp_posts database scanner
    ├── class-users-table-discovery.php # Users table discovery and metadata
    ├── class-users-table-reader.php # wp_users table reader
    ├── class-user-activity-reader.php # Per-user database activity reader
    ├── class-user-usermeta-reader.php # Per-user usermeta reader
    ├── class-user-file-activity-scanner.php # Per-user code-directory grep scanner
    ├── class-xml-rpc-protection.php # XML-RPC blocking
    └── class-login-rate-limiter.php # Login rate limiting
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full release history.

### 1.9.2

- Renamed product identity to **CoreGuard** (plugin folder `coreguard`) with top-level admin menu (Home, Settings, Scans, About)
- Expanded Scans reporting architecture across File Changes, Exposed Files, Uploads Folder, MU-Plugins, Directory Browsing, Verify Checksums, WP-Cron, wp_options, wp_posts, and Unrecognized Components
- **Vulnerabilities** now scans inactive themes/plugins and resolves child-theme parents as active for CVE checks
- Added WordPress Tables prefix setting and shared report Status / dismiss controls

### 1.9.1

- Added **Home** admin tab (default) with Status and Recent Lockouts
- Renamed **Main** tab label to **Settings**
- **wp_users View activity** now includes Usermeta Table and File Activity tabs alongside Database Activity
- About This Plugin: Important Please Read First section, Credits heading, and smaller logo

### 1.8.1

- **Verify Checksums** report shows one unified table (Modified, Missing, Not Part of Core) with Risk/Category filters and eye-expand remediation guidance, or an empty investigation list when clean

### 1.8.0

- Added **Vulnerabilities** admin tab — checks WordPress core, active theme, and active plugins against the WPVulnerability API
- Four report sections with expandable green/red component rows and inline CVE detail
- Lists installed plugins and themes not recognized by the API

### 1.7.0

- Added **wp_posts** admin tab with malware pattern scanning, baseline change tracking, and AJAX report UI
- User ID column shows `post_author` with display name on hover via paired users table lookup

### 1.6.0

- Added **wp_users** admin tab with sortable user list, pagination, and per-user View activity forensic drill-down
- Renamed **Database Scan** admin tab label to **wp_options**

### 1.5.2

- Database Scan now flags `phar://` in PHP & Execution Patterns and Cron Events suspicious payload checks

### 1.5.1

- Cron Events now reports a classified inventory of stored jobs, including WP Core labels and the `option_id` for the underlying `cron` option row

### 1.5.0

- Refactored Database Scan reports to an AJAX/JSON UI with no-reload scanning, client-side pagination, sortable columns, and a bottom rescan button

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

Sashtastic, LLC
