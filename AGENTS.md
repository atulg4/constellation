# atulg4/constellation Agent Guide

## Authority

The repository owner defines product intent and remains the final merge
authority. Codex is the primary architect, planner, and independent reviewer.
Codex or Claude Code may implement an explicitly approved work request.

## Required Workflow

1. Read the relevant code and repository instructions before proposing changes.
2. Require complete acceptance criteria, tests, non-goals, and dependencies.
3. Plan before implementation.
4. Add or update deterministic tests for changed behavior.
5. Make the smallest scoped implementation.
6. Run every configured verification gate.
7. Open a draft change request only. Never merge, approve, or deploy.

The controlling machine-readable policy is `agentic-sdlc.toml`.
