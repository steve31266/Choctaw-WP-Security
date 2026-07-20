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

## Finding object (common public envelope)

There is **one** public finding shape for all scanners. Heuristic fields belong inside this envelope; they do not define a second finding type. Product rules: [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md).

Illustrative shape (not yet frozen as formal JSON Schema files):

```json
{
  "schema_version": "1.0",
  "finding_id": "cgf_...",
  "site_id": "cgs_...",
  "scanner_id": "uploads",
  "rule_id": "php-file-in-uploads",
  "object": {
    "type": "file",
    "key": "wp-content/uploads/2026/07/example.php"
  },
  "risk_level": "critical",
  "coreguard_classification": "needs_review",
  "effective_status": "needs_review",
  "content_fingerprint": "sha256:...",
  "object_fingerprint": "sha256:...",
  "title": "Optional short label",
  "why_seeing_this": "…",
  "how_to_proceed": "…",
  "family": "iframe",
  "pack_id": "coreguard.iframe",
  "pack_version": "1.0.0",
  "profile_ids": ["unsafe_src_http"],
  "evidence": [
    {
      "type": "field_snippet",
      "location": "post_content",
      "post_id": 123,
      "snippet": "…"
    }
  ],
  "scanner_metadata": {},
  "first_seen_at": "2026-07-10T14:30:00Z",
  "last_seen_at": "2026-07-16T20:15:00Z",
  "detection_state": "active",
  "dismissal": null,
  "related_findings": []
}
```

| Field | Notes |
|---|---|
| `finding_id` | Stable opaque id for the logical finding |
| `content_fingerprint` | Rule-specific finding fingerprint; used for dismissal validity; **must not** include pack/profile versions |
| `object_fingerprint` | Whole-object version for related-finding context (files: normally entire-file SHA-256) |
| `coreguard_classification` | Machine: `needs_review` \| `no_action_needed` (label: Review Not Needed) — assigned by CoreGuard only |
| `effective_status` | `needs_review` \| `no_action_needed` \| `dismissed` — `dismissed` is a human override, not a scanner classification |
| `risk_level` | Canonical: `critical` \| `warning` \| `suspicious` \| `info` \| `safe`. Public field name is `risk_level`. Legacy `risk` may be adapted during migration. Independent of classification (default mapping in Findings System §3.5) |
| `evidence` | **Array** of structured evidence entries (heuristic-compatible); final allowed shapes and CLI-safe exposure TBD |
| `related_findings` | Present on `findings get`; omitted from list by default; bounded summary, not full payloads |
| Pack files | **Not** exposed; pack metadata on the finding is sufficient |

**Severity order:** `safe < info < suspicious < warning < critical`. Semantic colors are UI concerns; never color-only.

**v1 deferred:** `accepted` as a status. Alternate naming (`why` / `how`) may be normalized before freeze.

Legacy note: older drafts used a single `fingerprint` + `status` field and non-canonical risks (`alert`, `review`). Map those during scanner migration; do not keep a parallel heuristic-only finding type.

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

## Related Docs and Plans

- [CoreGuard Findings System.md](CoreGuard%20Findings%20System.md) — persistence, dismissal, correlation, migration
- [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) — list / get / dismiss / undismiss
- Heuristic engine plans must align with this envelope: [shared_heuristics_architecture.plan.md](../.cursor/plans/shared_heuristics_architecture.plan.md)

Schema and enum freezes are recorded here and in [Version Compatibility](CoreGuard%20Version%20Compatibility.md)—not only in Cursor plans.

## Open Items

- Formal JSON Schema (Draft 2020-12) files under `docs/schema/` or shipped with the plugin.
- Allowed `evidence[]` entry shapes and CLI-safe redaction rules.
- Whether `errors` live only on the envelope or also inside scan `data`.
- Pagination / cursor model.
- Exact public representation of `installation_id` / `site_id` on the wire (Site Identity specification).
- Optional scan-run attribution fields on list/get once Scan Site exists.
