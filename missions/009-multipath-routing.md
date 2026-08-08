# Mission 009 - Multipath Routing

## Summary

Add controlled multipath transfer and replication for resilience and large-object delivery.

## Acceptance Criteria

- [ ] Router can split transfer across feasible paths.
- [ ] Replication remains budgeted.
- [ ] Duplicate chunks are deduplicated.

## Required Tests

- Multipath simulation.
- Partial path failure tests.

## Non-Goals

- Unbounded flooding.

## Dependencies

Missions 005 and 007.

