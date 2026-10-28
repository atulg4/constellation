# constellation — working agreement for Claude Code

Read `AGENTS.md` first; it is the authoritative agent guide. Highlights:

- **Claim first.** Work only on an issue you lease (`sdlcctl claim … --session <your session id>`);
  the SessionStart hook prints the id and which issues other agents hold. The commit guard blocks
  every git command but read-only ones on `*/issue-N` branches without your lease.
- **Tests first.** Every change ships with tests. Run `cargo test --workspace --locked` before
  proposing a change.
- **Merge authority is the repository owner.** Agents open draft PRs only; never merge,
  approve, or deploy.
- **Never touch** `forbidden_paths` from `agentic-sdlc.toml` (workflows, policy, secrets,
  media, data).
- Work requests must follow `.github/ISSUE_TEMPLATE/agent-work-request.md` exactly
  (`## Summary`, `## Acceptance Criteria`, `## Required Tests`, `## Non-Goals`, `## Dependencies`;
  the last two as bullet lists, dependencies as `#N` references or `None`).
