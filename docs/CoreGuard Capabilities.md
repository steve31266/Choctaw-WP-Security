# CoreGuard Capabilities

> Status: Draft scaffold. Master inventory of features exposed to external applications. IDs and CLI mappings will be refined as commands are implemented.

## Purpose

Capabilities describe **what** CoreGuard can do for an external consumer, independent of PHP class names or admin UI tabs. Desktop (and other clients) should prefer capability IDs from `wp coreguard capabilities` over hard-coding assumptions about plugin internals.

## Capability ID Conventions (expected)

```text
area.action          e.g. findings.list
area.resource        e.g. scan.uploads_php
area.action.detail   e.g. settings.set
```

Use stable, lowercase, dotted IDs. Adding a capability is additive within an `api_version`; removing or redefining one is breaking.

---

## Inventory

### Meta / platform

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `meta.status` | Plugin present; versions; basic health | `wp coreguard status` |
| `meta.capabilities` | List supported capability IDs | `wp coreguard capabilities` |

### Scans

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `scan.list` | Enumerate available scans | `wp coreguard scan list` |
| `scan.run` | Run a scan by id | `wp coreguard scan run <scan-id>` |
| `scan.uploads_php` | Uploads PHP / executable lockdown related scan | `scan run uploads-php` |
| `scan.core_checksum` | Core file checksum verification | `scan run core-checksum` |
| `scan.posts` | Posts table heuristic / pattern scan | `scan run posts` |
| `scan.options` | Options table scan | `scan run options` |
| `scan.exposed_files` | Sensitive / exposed files | `scan run exposed-files` |
| `scan.scheduled_tasks` | Cron / scheduled task review | `scan run scheduled-tasks` |
| `scan.directory_browsing` | Directory browsing: `.htaccess` posture + HTTP tests of plugins/themes/uploads roots | `scan run directory-browsing` |
| `scan.mu_plugins` | Must-use plugins inventory/scan | `scan run mu-plugins` |
| `scan.component_vulnerabilities` | Plugin/theme vulnerability intel | `scan run component-vulnerabilities` |
| `scan.file_changes` | User / file activity related checks | `scan run file-changes` |
| `scan.users` | Users table discovery / review | `scan run users` |

Scan IDs above are illustrative of current plugin feature areas; normalize IDs when the CLI ships.

Heuristic-backed scans return fields compatible with the **common public finding envelope** (`family`, `pack_id`, `pack_version`, `profile_ids`, `evidence[]`, `risk_level` / risk, why/how, fingerprints). Pack files remain private. See [JSON Schema](CoreGuard%20JSON%20Schema.md) and [Findings System](CoreGuard%20Findings%20System.md).

### Findings

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `findings.list` | List/filter findings | `wp coreguard findings list` |
| `findings.get` | Fetch one finding (includes related summary) | `wp coreguard findings get` |
| `findings.dismiss` | Dismiss with reviewed finding fingerprint | `wp coreguard findings dismiss` |
| `findings.undismiss` | Undo / return to Needs Review (append-only history) | `wp coreguard findings undismiss` |

**Deferred for v1:** `findings.set_status` / free-form status assignment, including any `accepted` status. Classification (`needs_review` / `no_action_needed`) is assigned by CoreGuard only.

### Settings / hardening

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `settings.list` | List settings keys and values | `wp coreguard settings list` |
| `settings.get` | Read one setting | `wp coreguard settings get` |
| `settings.set` | Update one setting (validated in-plugin) | `wp coreguard settings set` |
| `hardening.xmlrpc` | XML-RPC protection related setting/action | via `settings` and/or `actions` |
| `hardening.login_rate_limit` | Login lockout / rate limit | via `settings` |
| `hardening.username_discovery` | Username discovery protection | via `settings` |
| `hardening.uploads_php_lockdown` | Uploads PHP lockdown apply/status | via `settings` / `actions` |

Exact key names belong in settings docs once frozen.

### Actions (future)

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `actions.run` | Invoke a named one-shot action | `wp coreguard actions run <action-id>` |

Use for operations that are not a full scan and not a simple setting write.

### Reports (future)

| Capability ID | Description | CLI access (expected) |
|---|---|---|
| `report.summary` | Aggregate site security summary | `wp coreguard report summary` |
| `report.export` | Export findings/history slice | `wp coreguard report export` |

---

## Desktop Mapping Notes

- **Enhanced mode:** enable UI modules only when the corresponding capability is present.
- **Native mode (no CoreGuard):** Desktop may still offer its own SSH audits; those are **not** CoreGuard capabilities and must not reuse these IDs.
- Incomplete scans (`scan_incomplete`) are a result state, not a separate capability.

## Non-Capabilities (intentionally not exposed)

| Item | Reason |
|---|---|
| Raw heuristic pack JSON | Plugin-private; findings are the contract |
| Internal DB table schemas | Avoid coupling |
| Admin AJAX endpoints | Not the Desktop integration path |
| Engine operator vocabulary | Internal to packs/engine |

## Open Items

- Canonical scan-id ↔ capability-id table after CLI implementation.
- Whether each scan is its own capability or only `scan.run` + `scan.list` metadata.
- Version per capability vs global `api_version` only.
- Marking admin-only features that will never get CLI exposure.
