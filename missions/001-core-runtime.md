# Mission 001 - Core Runtime Three-Device Demo

## Summary

Build the smallest executable Constellation runtime that proves authenticated, encrypted, integrity-verified, one-hop store-carry-forward delivery without a central server.

## Scenario

Three physical or simulated-then-physical devices: A, B, C. No Internet path is required for the target device demo.

1. A creates a text object or small file for C.
2. A discovers B over a local foreground transport.
3. A transfers the signed encrypted object to B.
4. B verifies envelope integrity and accepts custody without plaintext access.
5. A disappears.
6. B later discovers C.
7. B forwards the object to C.
8. C verifies creator identity, device signature, object integrity, TTL, duplicate status, and recipient authorization.
9. C decrypts the payload.

## Acceptance Criteria

- [ ] Object envelope has deterministic serialization and signature verification.
- [ ] Payload is encrypted before transfer and remains opaque to B.
- [ ] B can persist and later forward the object after A is unavailable.
- [ ] C rejects tampered envelopes, tampered payloads, expired objects, duplicate objects, and unauthorized-recipient objects.
- [ ] The demo runs with no central server.
- [ ] Delivery/custody state is observable without logging plaintext or secrets.

## Required Tests

- Unit tests for envelope canonicalization, signature verification, encryption/decryption, hash validation, TTL, and duplicate suppression.
- Deterministic simulator test for A -> B, then B -> C.
- Failure tests for tamper, wrong recipient, expired TTL, corrupted chunk, and duplicate delivery.
- One foreground physical-device smoke test using the selected local transport adapter.

## Non-Goals

- Background mesh routing.
- Multi-hop beyond one custody hop.
- Public relays.
- Large video transfer.
- Production identity recovery.
- MLS groups.
- Anonymous routing.

## Dependencies

Mission 000.

