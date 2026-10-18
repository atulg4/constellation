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
| `store` | Bounded custody store: size, count, per-peer and total quotas; TTL expiry; duplicate memory. `MemoryStore` lives for the process; `FileStore` persists under a directory. |
| `node` | Fixed-order validation pipeline, custody policy, decrypted inbox, privacy-safe events. |
| `transport` | The adapter trait and capability report platform transports will implement. |
| `sim` | Deterministic world: seeded RNG, manual clock, FIFO frames, explicit links. |

## Validation order

Frames are decoded canonically: bytes that are not exactly the canonical
re-encoding of what they decode to are dropped before validation.

An incoming object is checked in this order and the first failure is
reported in the ack and the receiver's event log:

0. duplicate: an envelope id already held or delivered is dropped before any
   signature, hash or decryption work
1. protocol version
2. ciphertext bound
3. encryption suite
4. creator user trusted
5. device authorization signature
6. envelope signature
7. TTL (`now >= expires_at` is expired) and clock skew
8. hop limit (clamped to local policy)
9. audience: addressed to this device and this user; otherwise custody
   policy, and custody is accepted only from the signed creator at hop 1
10. ciphertext hash and size against the signed commitment
11. decrypt into a bounded inbox (audience) or store under quota (carrier)

## Sender-side rules

- `submit` refuses a recipient record whose user-signed authorization does
  not verify or does not match its user, device and encryption key.
- `submit` expires stale objects before enforcing quotas.
- Custody is offered only to peers whose user is in the contact book.
- An acknowledgement releases a held object only if it comes from a peer the
  object was offered to. `Delivered` and `Duplicate` must come from the
  audience device; `CustodyAccepted` only applies to objects created here.
- Applications drain decrypted objects with `Node::take_inbox`; when the
  inbox is full, new deliveries are refused and stay with the sender.

## Scenarios covered by `tests/three_device.rs`

- A → B custody, A removed, B → C delivery, C decrypts; B drops its copy on ack.
- B's store and events contain no plaintext; B cannot open the payload; C can.
- Tampered envelope, corrupted ciphertext, wrong audience user, untrusted
  creator, unsupported version, expired object, duplicate, over-limit hop,
  second custody hop, quota exhaustion, oversized payload.
- Object ids are identical on every node and change per encryption.
- B accepts custody, its process restarts from the same directory with the
  same device identity, a re-sent copy is reported as a duplicate, B → C
  delivers, and no object bytes remain on disk.

## On-disk layout

`Node::persistent(device, contacts, policy, dir)` opens a `FileStore` under
`dir`:

```text
dir/
  objects/<object id, 64 hex chars>.cbor   one accepted object each
  seen.bin                                 concatenated 32-byte seen ids
```

Each object file is the canonical CBOR of a record holding the signed
envelope, the ciphertext, and the transport-local fields (`hop_count`,
`from`, `received_at`). Nothing is written until the validation pipeline has
accepted the object, and nothing written is ever plaintext or key material.
Writes go to a `.tmp` sibling, are synced, and are renamed into place, so a
crash leaves the old file or the new one. At open, every entry is bounded by
`MAX_FRAME_BYTES`, decoded, checked against its file name and the envelope's
payload size and hash, and inserted under the current quotas; entries that
fail are skipped and counted in `FileStore::rejected_at_load`. The seen set is
read back up to `MAX_SEEN_IDS` entries. Inbox contents and lifecycle events
are process-local and are not persisted.

## Assumptions and limits (Mission 001 only)

- Identities are static test material with no rotation, revocation or recovery.
- One audience device per object; one custody hop; no relays or routing.
- Duplicate memory grows without bound in memory; on disk it is capped at
  `MAX_SEEN_IDS` entries, and the inbox and event log are not persisted.
- `FileStore` is single-process: two nodes must not open the same directory.
- `Transport` has no implementation besides the simulator; the first
  physical smoke test (Multipeer / Nearby / LAN) is a separate change.
- Receipts are unsigned acks between peers in contact, not the signed
  custody receipts ADR-0008 describes for later missions. Peer identity in
  the simulator is taken as reported; a real transport must authenticate the
  peer's device key before its `PeerInfo` is trusted.
