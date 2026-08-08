# Mission 005 - Routing Store-Forward

## Summary

Extend one-hop custody into controlled multi-hop store-forward routing with strict budgets.

## Acceptance Criteria

- [ ] Routing strategies are pluggable.
- [ ] TTL, hop limits, quotas, and trust scopes are enforced.
- [ ] Naive flooding is not the default.

## Required Tests

- Partition simulation.
- Multi-hop delayed delivery simulation.
- Malicious peer and resource exhaustion tests.

## Non-Goals

- Global routing guarantees.
- Anonymous routing.

## Dependencies

Missions 003 and 004.

