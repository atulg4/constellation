# Forge pod migration

## Cutover status

Blocked pending a compatible runner sandbox. The live GKE Sandbox probe on
2026-10-02 passed user namespaces but failed network isolation with
`bwrap: loopback: Failed RTM_NEWADDR: No child processes`. Keep this change in
draft and require a passing `Forge pod smoke` run before owner merge.

## Acceptance Criteria

All Forge jobs target `constellation-runners`, including reusable workflow
jobs. The pool has zero idle workers. `Forge pod smoke` proves tools, bubblewrap
and artifact handoff between two different ephemeral runner pods.

## Required Tests

Run `python3 -m unittest discover -s .github/tests -p 'test_*.py'` with PyYAML
installed, lint the workflows, and pass the repository's existing CI and review
gates. Require the live pod smoke workflow to pass before owner merge.

## Non-Goals

No model/provider changes, production deployment, brokerage access, PR approval
or merge. Docker-dependent jobs and application deployment jobs retain their
GitHub-hosted runners. Existing security and review gates stay in force.

## Dependencies

The ARC pool, the pinned Forge runner image, and GKE Sandbox must be validated
in the CI cluster. The fleet values and rollout instructions are maintained in
`atulg4/agentic-sdlc` under `infra/arc`. Set the repository Actions variable
`FORGE_RUNNER=constellation-runners` for future generated workflows.

Rollback requires restoring the prior reviewed workflow commit and the previous
ARC Helm revision; stopped VM runners are not restarted automatically.

## Older Forge interface

The pinned Forge release `2213ee45859eaea46a177fd3cdbafe812901b205` does
not declare `runs_on`. The two `forge-compat-*.yml` workflows are exact copies
of its reusable plan/implementation workflows with only runner input/selection
added. The policy-engine SHA, models, credentials, publishing gates and action
pins remain unchanged. `test_forge_compatibility.py` checks byte hashes after
removing those routing changes. Keep these copies until a separately reviewed
Forge upgrade preserves or deliberately changes the provider/authentication
contract; then remove both compatibility files and their test together.
