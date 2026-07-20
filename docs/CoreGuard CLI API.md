# CoreGuard CLI API

> Status: Draft scaffold. Command names and options below are expected shapes based on product plans; refine as implementation lands.

## Conventions

- All integration-facing commands support `--format=json` (required for Desktop).
- Responses follow the [JSON Schema](CoreGuard%20JSON%20Schema.md) envelope.
- Exit codes: `0` success; non-zero for hard failures (invalid args, missing capability, WP-CLI errors). Soft failures (e.g. incomplete scan) may still exit `0` with `success: false` or `scan_incomplete` in JSON—**to be confirmed**.
- Command namespace: `wp coreguard …`

## Expected Command Groups

| Group | Purpose |
|---|---|
| `status` | Plugin presence, versions, health summary |
| `capabilities` | List what this install supports |
| `scan` | Run or inspect scans |
| `findings` | List / get findings; dismiss / undismiss with fingerprint validation |
| `settings` | Read and update plugin settings |
| `report` | Aggregate or export report data (future) |
| `actions` | One-shot remediation or hardening actions (future) |

---

## `wp coreguard status`

**Purpose:** Confirm CoreGuard is installed and report version / API info.

**Syntax (expected):**

```text
wp coreguard status [--format=json]
```

**Behavior:** Returns plugin version, CLI `api_version`, and a short operational summary (e.g. last scan time if available).

**Example:**

```bash
wp coreguard status --format=json
```

---

## `wp coreguard capabilities`

**Purpose:** Advertise supported features so Desktop can enable/disable UI without probing every command.

**Syntax (expected):**

```text
wp coreguard capabilities [--format=json]
```

**Behavior:** Returns capability IDs aligned with [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md).

---

## `wp coreguard scan`

### `scan run`

**Purpose:** Execute a named scan (or scan family).

**Syntax (expected):**

```text
wp coreguard scan run <scan-id> [--format=json] [--async] [--force]
```

| Argument / option | Description |
|---|---|
| `<scan-id>` | Stable ID (e.g. `uploads-php`, `core-checksum`, `posts`, `options`, `exposed-files`, `scheduled-tasks`, …) |
| `--async` | Optional: queue and return job id (if supported later) |
| `--force` | Optional: ignore cache / cooldown |

**Behavior:** Runs the scan in-plugin; returns findings summary and/or finding list. Pack/engine failures must surface as incomplete (`scan_incomplete` + `errors[]`), not a false clean.

**Example:**

```bash
wp coreguard scan run uploads-php --format=json
```

### `scan list`

**Purpose:** Enumerate available scan IDs and metadata.

```text
wp coreguard scan list [--format=json]
```

### `scan status` (optional / future)

```text
wp coreguard scan status [<job-id>] [--format=json]
```

---

## `wp coreguard findings`

Canonical product requirements: [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md).

**v1 status values (effective status filter):** `needs_review`, `no_action_needed`, `dismissed`.  
**Deferred / non-goal for v1:** an `accepted` status. Free-form `findings set-status` that can assign CoreGuard classifications is **not** part of v1.

### `findings list`

**Purpose:** List findings with filters. Does **not** expand `related_findings` by default.

```text
wp coreguard findings list [--format=json] [--scan=<id>] [--status=<status>] [--risk=<risk>] [--limit=<n>] [--offset=<n>]
```

| Option | Expected values |
|---|---|
| `--status` | Effective status: `needs_review`, `no_action_needed`, `dismissed` |
| `--risk` | Canonical `risk_level`: `critical`, `warning`, `suspicious`, `info`, `safe` |

**Finding fields:** Use the **common public finding envelope** in [JSON Schema](CoreGuard%20JSON%20Schema.md). Heuristic metadata (`family`, `pack_id`, `pack_version`, `profile_ids`, `evidence[]`) lives inside that envelope (e.g. top-level optional fields and/or `scanner_metadata`), not as a second finding type. Finding fingerprint (`content_fingerprint`) and object fingerprint are separate; fingerprints must **not** embed pack/profile versions.

### `findings get`

```text
wp coreguard findings get <finding-id> [--format=json]
```

Returns one finding in the common envelope, including a bounded `related_findings` summary when applicable (see Findings System PRD §5.7). Identifier is the stable `finding_id` (opaque); legacy fingerprint-or-id lookup may be considered during migration but is not the long-term public key.

### `findings dismiss`

```text
wp coreguard findings dismiss <finding-id> --fingerprint=<reviewed-finding-fingerprint> [--format=json] [--source=desktop] [--note=...]
```

Creates a new append-only dismissal decision for the reviewed **finding** fingerprint. Rejects when the fingerprint does not match the current finding version. Desktop never writes findings tables directly.

### `findings undismiss`

```text
wp coreguard findings undismiss <finding-id> [--format=json] [--source=desktop]
```

Terminates the currently valid dismissal (history retained); effective status returns to Needs Review when classification is still `needs_review`.

---

## `wp coreguard settings`

### `settings list`

```text
wp coreguard settings list [--format=json]
```

### `settings get`

```text
wp coreguard settings get <key> [--format=json]
```

### `settings set`

```text
wp coreguard settings set <key> <value> [--format=json]
```

**Example:**

```bash
wp coreguard settings set disable_xmlrpc true --format=json
```

**Behavior:** Plugin validates values, enforces dependencies, updates options / server config where supported, and may return warnings when manual follow-up is required. Desktop must not edit options tables or files directly.

---

## `wp coreguard report` (future)

Expected direction: aggregate status across scans/findings for historical or export use.

```text
wp coreguard report summary [--format=json]
wp coreguard report export [--format=json] [--since=...]
```

---

## Exit Codes (provisional)

| Code | Meaning |
|---|---|
| `0` | Command completed; inspect JSON for `success` / incomplete flags |
| `1` | General error (invalid args, runtime failure) |
| `2` | CoreGuard not available / insufficient capability (TBD) |

Exact mapping will be frozen with `api_version` 1.

## Error Behavior

- Hard errors: non-zero exit + JSON error object when possible.
- Soft / partial: JSON indicates incomplete or warning; consumers must not treat incomplete as clean.

## Open Items

- Final scan-id taxonomy.
- Sync vs async scan model for long jobs.
- Pagination defaults and max limits.
- Whether human (table) format is supported alongside JSON.
- WP-CLI permission model (`--user`, capability checks).
