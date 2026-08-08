---
name: Agent work request
about: A complete request that can be planned and implemented by the pipeline
title: "Mission 001: Build core runtime three-device store-carry-forward demo"
labels: agent-ready, human-review-required
assignees: ""
---

## Summary

Build the smallest executable Constellation runtime that proves authenticated, encrypted, integrity-verified, one-hop store-carry-forward delivery without a central server. Device A creates an object for C, transfers it to B, disappears, and B later forwards it to C.

## Acceptance Criteria

- [ ] A can create a canonical signed envelope for a text object or small file.
- [ ] Payload content is encrypted for C before transfer and remains opaque to B.
- [ ] B can verify the envelope, accept bounded custody, persist the object, and forward it later.
- [ ] C verifies creator identity, device signature, object integrity, TTL, duplicate status, and authorization before decryption.
- [ ] Tampered, expired, duplicate, corrupted, and unauthorized-recipient objects are rejected.
- [ ] The demo requires no central server.

## Required Tests

- Add deterministic unit tests for envelope canonicalization, signature verification, encryption/decryption, hash validation, TTL, and duplicate suppression.
- Add simulator tests for A to B custody and later B to C delivery.
- Add failure tests for tampering, wrong recipient, expiration, corruption, and duplicate delivery.
- Add one foreground physical-device smoke test plan for the selected local transport adapter.

## Non-Goals

- Background mesh routing.
- Public relays.
- Multi-hop routing beyond one custody hop.
- Large video transfer.
- Production identity recovery.
- Anonymous routing.

## Dependencies

None
