# Mission 001 Runtime

`crates/constellation-core` is the first executable Constellation code. It
proves the Mission 001 scenario in a deterministic simulator and is the
library a platform adapter will link against. Decisions are in
[ADR-0011](adr/ADR-0011-mission-001-protocol-profile.md).

## Running

```bash
cargo test
```

The crate has no binary. `tests/three_device.rs` is the executable form of
the mission's acceptance criteria.

## What exists

| Module | Responsibility |
| --- | --- |
| `identity` | User root key, device keys, signed device authorization, contact trust. |
| `envelope` | Canonical signed envelope, object id, wire frames with bounded decode. |
| `crypto` | HPKE sealing and opening, SHA-256, payload AAD. No primitives. |
| `store` | Bounded in-memory custody store: size, count, per-peer and total quotas; TTL expiry; duplicate memory. |
| `node` | Fixed-order validation pipeline, custody policy, decrypted inbox, privacy-safe events. |
| `transport` | The adapter trait and capability report platform transports will implement. |
| `sim` | Deterministic world: seeded RNG, manual clock, FIFO frames, explicit links. |

## Validation order

An incoming object is checked in this order and the first failure is
reported in the ack and the receiver's event log:

1. protocol version
2. ciphertext bound
3. encryption suite
4. creator user trusted
5. device authorization signature
6. envelope signature
7. TTL (`now >= expires_at` is expired) and clock skew
8. hop limit (clamped to local policy)
9. audience: addressed to this device and this user, else custody policy
10. ciphertext hash and size against the signed commitment
11. duplicate
12. decrypt (audience) or store under quota (carrier)

## Scenarios covered by `tests/three_device.rs`

- A → B custody, A removed, B → C delivery, C decrypts; B drops its copy on ack.
- B's store and events contain no plaintext; B cannot open the payload; C can.
- Tampered envelope, corrupted ciphertext, wrong audience user, untrusted
  creator, unsupported version, expired object, duplicate, over-limit hop,
  second custody hop, quota exhaustion, oversized payload.
- Object ids are identical on every node and change per encryption.

## Assumptions and limits (Mission 001 only)

- Identities are static test material with no rotation, revocation or recovery.
- One audience device per object; one custody hop; no relays or routing.
- The store is in-memory; persistence across restart is not implemented.
- Duplicate memory grows without bound for the process lifetime.
- `Transport` has no implementation besides the simulator; the first
  physical smoke test (Multipeer / Nearby / LAN) is a separate change.
- Receipts are unsigned acks between peers in contact, not the signed
  custody receipts ADR-0008 describes for later missions.
