# CoreGuard Desktop Integration

> Status: Draft scaffold. CoreGuard Desktop (internally WPASSH) is planned at https://github.com/steve31266/wpassh. Integration details will firm up when Desktop development begins.

## Products and Independence

| Product | Role |
|---|---|
| **CoreGuard Plugin** (free) | Security engine for one WordPress site: hardening, scans, findings, local settings, remediation guidance. |
| **CoreGuard Desktop** (commercial) | Operations console for many sites over SSH: inventory, monitoring, bulk ops, history, notifications, remote config. |

Neither product requires the other to function. Value increases when they are used together.

## Integration Model

When CoreGuard is installed on a site, Desktop communicates **only** through the versioned WP-CLI JSON API documented in this folder.

```text
CoreGuard Desktop
  → SSH session to host
    → wp coreguard … --format=json
      → Plugin validates / executes
        → JSON envelope back to Desktop
```

### Desktop must not

- Execute plugin PHP files directly.
- Read or modify plugin internal DB schemas or options tables.
- Read heuristic pack JSON from disk (`data/heuristics/*.json`).
- Depend on admin UI URLs, nonce flows, or undocumented hooks for automation.
- Assume filesystem layout beyond what WP-CLI needs to run.

### Plugin must

- Keep business logic (detection, risk, validation, persistence) in-plugin.
- Expose capabilities via documented commands.
- Return stable, versioned JSON.
- Fail loudly on incomplete scans (`scan_incomplete` + errors), never as false clean.

## Discovery Flow (expected)

1. Connect over SSH; confirm WordPress + WP-CLI available.
2. Probe CoreGuard: `wp coreguard status --format=json` (or equivalent).
3. Read `api_version` / `plugin_version`; apply [compatibility](CoreGuard%20Version%20Compatibility.md) rules.
4. Optionally call `wp coreguard capabilities --format=json` to enable enhanced features in the UI.
5. If CoreGuard is absent, fall back to **native** audits only.

## Native vs Enhanced Audits

| Mode | When | Examples |
|---|---|---|
| **Native** | Any WordPress site over SSH | WP version, core/plugin checksums via WP-CLI core tools, PHP in uploads heuristics Desktop owns, update detection, disk/SSL/PHP version, server health |
| **Enhanced** | CoreGuard installed | Plugin scans, heuristic findings with why/how, finding status, plugin settings, CoreGuard-specific reports |

Agencies can manage mixed fleets: some sites enhanced, some native-only.

## Responsibility Split

### Desktop owns

- Multi-site dashboard and inventory
- SSH credentials / connection lifecycle
- Scheduling and bulk orchestration
- Historical storage of CLI results (client-side)
- Notifications and agency workflows
- UI for comparing sites and trends
- Native audits where CoreGuard is not installed
- Detecting API incompatibility and prompting upgrades

### Plugin owns

- WordPress-specific security knowledge
- Heuristic packs and evaluation engine
- Risk classification, CoreGuard classification, and finding explanations
- Findings persistence and dismiss / undismiss decisions (plugin authoritative when installed)
- Local scan execution and settings validation
- Server config writes where the plugin supports them (e.g. lockdowns)
- Warnings when remote set requires manual server action

### Shared contract

- Command names, arguments, JSON shapes, capability IDs, and versioning rules in these docs.

## Settings and Remote Configuration

Desktop may change settings via:

```bash
wp coreguard settings list --format=json
wp coreguard settings set <key> <value> --format=json
```

Overrides of heuristic behavior (when offered) go through plugin settings/CLI—not by editing bundled pack files on disk.

## Findings Workflow (expected)

Canonical requirements: [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md).

1. Desktop triggers `scan run` or reads cached findings via `findings list`.
2. User reviews why/how/`evidence[]` in Desktop UI (data from the common finding envelope).
3. Dismissal: `findings dismiss <finding-id> --fingerprint=<reviewed-finding-fingerprint>`; plugin validates and appends a decision record.
4. Undo: `findings undismiss <finding-id>`; plugin terminates the current decision without erasing history.
5. `findings get` may include related findings for the same object (context only; no cross-scan dismissal inheritance).
6. Desktop may keep its own history copy but treats plugin findings and review state as source of truth for the site when the plugin is installed.

**v1 non-goals for Desktop↔plugin:** `accepted` status; free-form `set-status`; writing findings tables over SSH outside CLI.

## Loose Coupling Checklist

- [ ] All enhanced features reachable via documented CLI.
- [ ] No Desktop code imports or parses pack files.
- [ ] Compatibility decided from envelope versions, not file sniffing.
- [ ] New plugin features ship with CLI exposure (or explicit “admin-only” note).
- [ ] Breaking changes bump `api_version` and are called out in compatibility docs.

## Related Docs and Plans

- [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md) — findings authority, dismiss/undismiss, correlation
- [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md) — in-plugin engine; packs private; findings match [JSON Schema](CoreGuard%20JSON%20Schema.md)
- [iframe_tag_inspection.plan.md](../.cursor/plans/iframe_tag_inspection.plan.md) — first family consumer
- [Plugin and Desktop Application Relationship](../.cursor/plans/Plugin%20and%20Desktop%20Application%20Relationship.md) — product philosophy

New Desktop/CLI decisions belong in this `docs/` folder (see [README.md](README.md)), not only in Cursor plans.

## Open Items

- Connection pooling / timeout / long-scan UX.
- How Desktop stores and syncs historical reports (local cache vs plugin authority already specified for live status).
- Multi-site bulk scan concurrency limits.
- Auth model when SSH user maps to a specific WP user (`wp --user=`) and how that maps to dismissal `actor_*` fields.
- Offline / reachability states in the Desktop UI.
- Site Identity specification (`installation_id` / `site_id` encoding and cloning).
- Multisite: network-wide CoreGuard (Super Admin only); `blog_id` in object identity for subsite-owned findings — see [Findings System](CoreGuard%20Findings%20System.md) §3.10.
- Future Scan Site / scheduled / Home / email consumers share the same Findings store; Desktop orchestration remains a later phase.
