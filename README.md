# Choctaw WP Security

A lightweight WordPress security plugin that hardens two common attack paths:

1. **XML-RPC abuse** — blocks unauthorized XML-RPC access
2. **Login brute force** — rate-limits failed `wp-login.php` attempts

Built for simple deployment on shared hosting (e.g. DreamHost/DreamPress). No Composer, build tools, or external dependencies.

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

## Requirements

- WordPress **5.8+**
- PHP **7.4+**

## Installation

1. Copy the plugin folder to your WordPress site:

   ```
   wp-content/plugins/choctaw-wp-security/
   ```

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
- [ ] Disabling XML-RPC blocking from settings stops XML-RPC blocking through this plugin
- [ ] Disabling login rate limiting from settings stops login blocking through this plugin

## Repository Layout

This repository contains the plugin source only. It is not a full WordPress installation.

Deploy by copying this folder into your site:

```
wp-content/plugins/choctaw-wp-security/
```

## Project Structure

```
wp-content/plugins/choctaw-wp-security/
├── choctaw-wp-security.php          # Bootstrap, constants, activation hook
├── assets/css/login-lockout.css     # Login lockout styling
└── includes/
    ├── class-plugin.php             # Module coordinator
    ├── class-utils.php              # Options, IP helper, transient keys
    ├── class-settings.php           # Admin settings page
    ├── class-xml-rpc-protection.php # XML-RPC blocking
    └── class-login-rate-limiter.php # Login rate limiting
```

## Changelog

### 1.0.1

- Improved lockout UX with styled login notice and early request intercept
- Fixed server 500 errors on some hosts when lockout was triggered

### 1.0.0

- Initial release: XML-RPC protection and dual-scope login rate limiting

## License

GPL-3.0-or-later

## Author

Choctaw Websites
