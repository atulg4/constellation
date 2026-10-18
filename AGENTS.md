# atulg4/constellation Agent Guide

## Authority

The repository owner defines product intent and remains the final merge authority.
Claude Code is the planner: the plan workflows (`agent-plan.yml`, `agent-auto-plan.yml`) run it
through the platform's `reusable-plan.yml`. Codex is the independent reviewer. The configured
implementer may implement an explicitly approved work request only.

## Required Workflow

0. **Claim before you code.** Every change maps to an issue. Lease it first
   (`sdlcctl claim --project atulg4/constellation --issue <N> --agent <you> --session <id>
   --branch forge/issue-<N>`);
   if the claim fails, run `sdlcctl release` with the same `--session` (best-effort: it retracts
   a claim marker left queued) and pick different work. Never work on an
   `in-progress` issue you do not hold. Release (or let the draft PR stand in) when done.
1. Read the relevant code and repository instructions before proposing changes; `git fetch` first.
2. Require complete acceptance criteria, tests, non-goals, and dependencies in the issue.
3. Plan before implementation.
4. Add or update deterministic tests for changed behavior (tests first).
5. Make the smallest scoped implementation; stay within the patch caps in `agentic-sdlc.toml`.
6. Run every configured verification gate locally before opening a change request.
7. Open a draft change request only. Never merge, approve, or deploy.

## Product Invariants

- Verification must not call production systems, paid AI providers, or deployment targets.
- Never commit media, user data, credentials, or `.env*` files. `forbidden_paths` rejects
  image, video and audio files (SVG is source, reviewed like code), key files, SQLite
  databases and `.env*`; other user data is on you.
- Touching a `protected_paths` entry adds an architect/security review gate.

## Verification

```bash
cargo fetch --locked
cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The controlling machine-readable policy is `agentic-sdlc.toml`.

## Constellation notes

- Product intent lives in `docs/vision.md`, `docs/principles.md` and `missions/`; the
  protocol profile every change must respect is `docs/adr/ADR-0011-mission-001-protocol-profile.md`.
- `crates/constellation-core/src/crypto.rs` and `identity.rs` are protected paths: never add a
  cryptographic primitive, change the suite, or weaken a validation step without an ADR.
- Lifecycle events, logs and stores must never carry plaintext, private keys or raw peer ids.
