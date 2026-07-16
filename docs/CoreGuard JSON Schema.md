# CoreGuard JSON Schema

> Status: Draft scaffold. This is the intended data contract between the plugin CLI and consumers (e.g. CoreGuard Desktop). Field names may be refined before `api_version` 1 is frozen.

## Envelope (all commands)

Every JSON response should wrap payload data in a common envelope:

```json
{
  "api_version": 1,
  "plugin_version": "1.0.0",
  "success": true,
  "generated_at": "2026-07-12T12:00:00Z",
  "data": {},
  "errors": [],
  "warnings": []
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `api_version` | integer | yes | CLI contract version; Desktop uses this for compatibility |
| `plugin_version` | string | yes | SemVer of the plugin package |
| `success` | boolean | yes | `false` when the command failed or could not complete meaningfully |
| `generated_at` | string (ISO-8601 UTC) | yes | Response timestamp |
| `data` | object \| array \| null | yes | Command-specific payload |
| `errors` | array of error objects | no* | Present on failure or incomplete operations |
| `warnings` | array of strings/objects | no | Non-fatal issues (e.g. setting applied but server rewrite needed) |

\*Exact rules for when `errors` is omitted vs empty array TBD.

### Error object (expected)

```json
{
  "code": "pack_invalid",
  "message": "Heuristic pack coreguard.iframe failed validation.",
  "context": {}
}
```

---

## Status response (`data`)

Expected shape:

```json
{
  "plugin_name": "CoreGuard",
  "plugin_version": "1.0.0",
  "api_version": 1,
  "wordpress_version": "6.x.x",
  "site_url": "https://example.com",
  "healthy": true
}
```

Additional summary fields (last scan times, finding counts) may be added additively.

---

## Capabilities response (`data`)

```json
{
  "capabilities": [
    {
      "id": "scan.uploads_php",
      "version": 1
    },
    {
      "id": "findings.list",
      "version": 1
    }
  ]
}
```

Capability IDs should match [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md).

---

## Scan result (`data`)

Expected direction for `scan run`:

```json
{
  "scan_id": "uploads-php",
  "scan_incomplete": false,
  "started_at": "2026-07-12T12:00:00Z",
  "finished_at": "2026-07-12T12:00:05Z",
  "summary": {
    "findings_total": 2,
    "by_risk": {
      "critical": 1,
      "suspicious": 1
    }
  },
  "findings": [],
  "errors": []
}
```

**Incomplete ≠ clean:** If packs fail to load/validate or a subsystem errors, set `scan_incomplete: true` and populate `errors` (envelope and/or `data`). Consumers must never treat incomplete as a clean bill of health.

---

## Finding object

CLI-ready fields (aligned with shared heuristics architecture):

```json
{
  "fingerprint": "stable-scanner-owned-id",
  "scan_id": "posts",
  "family": "iframe",
  "pack_id": "coreguard.iframe",
  "pack_version": "1.0.0",
  "profile_ids": ["unsafe_src_http"],
  "risk": "critical",
  "status": "needs_review",
  "title": "Optional short label",
  "why_seeing_this": "…",
  "how_to_proceed": "…",
  "evidence": [
    {
      "type": "field_snippet",
      "location": "post_content",
      "post_id": 123,
      "snippet": "…"
    }
  ],
  "detected_at": "2026-07-12T12:00:00Z",
  "updated_at": "2026-07-12T12:00:00Z"
}
```

| Field | Notes |
|---|---|
| `fingerprint` | Stable; **must not** include pack/profile versions |
| `risk` | Engine v1: `critical` \| `suspicious` only; permanent published enum frozen under CLI `api_version` before Desktop ship; additive thereafter |
| `evidence` | Structured records, not free-form only |
| Pack files | **Not** exposed; metadata on the finding is sufficient |

Alternate naming (`why` / `how`) may be normalized before freeze—pick one public name and document aliases if needed.

---

## Findings list (`data`)

```json
{
  "total": 42,
  "limit": 50,
  "offset": 0,
  "items": []
}
```

---

## Settings (`data`)

**List / get:**

```json
{
  "settings": [
    {
      "key": "disable_xmlrpc",
      "value": true,
      "type": "boolean",
      "writable": true
    }
  ]
}
```

**Set result:**

```json
{
  "key": "disable_xmlrpc",
  "value": true,
  "applied": true,
  "requires_manual_action": false,
  "message": null
}
```

Plugin validates and may return warnings when configuration cannot be fully applied remotely.

---

## Versioning of this schema

- Breaking changes require a new `api_version`.
- Additive fields are preferred within a major API version.
- See [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md).

## Related Plans

Heuristic findings produced by the shared engine must remain compatible with the **Finding object** above so CLI/Desktop can expose them without reading pack files. See [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md).

Schema and enum freezes are recorded here and in [Version Compatibility](CoreGuard%20Version%20Compatibility.md)—not only in Cursor plans.

## Open Items

- Formal JSON Schema (Draft 2020-12) files under `docs/schema/` or shipped with the plugin.
- Canonical risk enum freeze date and values beyond v1.
- Finding status enum names.
- Whether `errors` live only on the envelope or also inside scan `data`.
- Pagination / cursor model.
