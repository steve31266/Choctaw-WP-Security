# CoreGuard CLI Overview

> Status: Draft scaffold. Refine as the WP-CLI surface and Desktop product mature.

## Purpose

The CoreGuard Command-Line Interface (CLI) is the **public API** of the CoreGuard WordPress plugin. It exposes security capabilities—scans, findings, settings, status, and related actions—through versioned WP-CLI commands that return structured JSON.

External applications, especially **CoreGuard Desktop** (WPASSH), interact with CoreGuard **only** through this interface. They must not execute plugin PHP directly, read heuristic pack files, or depend on internal database schemas.

## Design Philosophy

| Principle | Meaning |
|---|---|
| Plugin owns business logic | Detection, risk classification, validation, remediation guidance, and persistence stay inside the plugin. |
| CLI is a public contract | Commands and JSON responses are versioned and treated as a stable API. |
| Loose coupling | Desktop and plugin work independently; together they form an ecosystem. |
| JSON over prose | Machine-consumable responses (`--format=json`) are the integration path; human text is secondary. |
| Capability, not implementation | Consumers ask for outcomes (run a scan, list findings); they do not need to know how packs, extractors, or scanners work. |

## Who Uses the CLI

1. **CoreGuard Desktop** — multi-site operations over SSH; primary consumer of the versioned JSON API.
2. **Site operators / agencies** — ad-hoc audits and automation from the shell.
3. **Future tooling** — scripts, CI, hosting panels, or other clients that speak WP-CLI.

## How External Apps Interact

```text
Desktop / client
    → SSH (or local shell)
        → wp coreguard <command> --format=json
            → CoreGuard plugin (business logic)
                → JSON envelope (api_version, plugin_version, success, data, …)
```

Typical flow:

1. Discover whether CoreGuard is installed and which API version it speaks (`status` / capability probe).
2. Invoke versioned commands for scans, findings, settings, and actions.
3. Parse the JSON envelope; respect `success`, errors, and incomplete-scan signals.
4. Never bypass the CLI for remote configuration or finding dismiss / undismiss actions.

## Source of Truth

Desktop and CLI API decisions are recorded in this `docs/` library (see [README.md](README.md)). Enhancement plans under `.cursor/plans/` should link here and stay consistent with these contracts; they should not redefine the public API in isolation.

## Document Map

| Document | Role |
|---|---|
| [README.md](README.md) | Library index and decision-recording policy. |
| [CHANGELOG.md](CHANGELOG.md) | Dated documentation / decision history (not the plugin release changelog). |
| [CoreGuard CLI API.md](CoreGuard%20CLI%20API.md) | Command reference (syntax, options, exit codes). |
| [CoreGuard JSON Schema.md](CoreGuard%20JSON%20Schema.md) | Response envelope and data contracts. |
| [CoreGuard Desktop Integration.md](CoreGuard%20Desktop%20Integration.md) | Discovery, SSH/WP-CLI usage, responsibility split. |
| [CoreGuard Version Compatibility.md](CoreGuard%20Version%20Compatibility.md) | Versioning, deprecation, incompatibility handling. |
| [CoreGuard Capabilities.md](CoreGuard%20Capabilities.md) | Feature inventory mapped to CLI commands. |

## Related Product Notes

- The plugin remains fully useful without Desktop.
- Desktop can still run **native** SSH/WP-CLI audits on sites without CoreGuard; **enhanced** audits require the plugin CLI.
- Heuristic packs under `data/heuristics/` are **plugin-private**. Finding payloads in CLI JSON are the public contract—not pack files.

## Open Items

- Exact command tree and subcommands (see CLI API draft).
- Authentication / capability checks for remote operators (WordPress roles vs SSH user).
- Streaming / long-running scan progress model (single JSON vs progress events).
- Formal OpenAPI-style schema publication timeline.
