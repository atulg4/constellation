# Mission 004 - Object Store

## Summary

Implement encrypted local storage for envelopes, manifests, chunks, receipts, and routing state.

## Acceptance Criteria

- [ ] Store enforces quotas, TTL, duplicate suppression, and garbage collection.
- [ ] Corrupted data is detected.
- [ ] Sensitive data is encrypted at rest where platform support allows.

## Required Tests

- Persistence tests.
- Quota/eviction tests.
- Corruption and recovery tests.

## Non-Goals

- Infinite retention.
- Public pinning network.

## Dependencies

Mission 001.

