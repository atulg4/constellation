# Constellation Mission 000

Constellation is an open, secure, decentralized, offline-first, transport-agnostic communication fabric for arbitrary application data.

The core objective is:

```text
Application -> Constellation -> best available path(s) -> Constellation -> Application
```

Mission 000 produces foundation artifacts only: architecture, research, threat model, ADRs, RFCs, native Agentic SDLC mission/work-request files, and review gates for Mission 001.

## Repository Map

- `crates/constellation-core/` - Mission 001 runtime: signed encrypted envelopes, bounded custody store, deterministic three-device simulator. Run `cargo test`.
- `docs/` - foundation architecture documents; `docs/mission-001-runtime.md` describes the runtime.
- `docs/research/` - structured evaluation of existing technologies.
- `docs/adr/` and `adrs/` - architecture decision records.
- `rfcs/` - protocol-facing design proposals.
- `missions/` - Agentic SDLC mission specifications.
- `work-requests/` - native Agentic SDLC work-request issues.
- `reviews/` - Mission 000 security and architecture gate results.

## Mission 000 Status

Mission 000 is complete as a documentation and review foundation. Mission 001 is scoped to prove authenticated, encrypted, integrity-verified, one-hop store-carry-forward delivery across three disconnected devices with no central server; its simulator-first core runtime lives in `crates/constellation-core` (see ADR-0011 for the protocol profile). The physical-device smoke test is still open.

