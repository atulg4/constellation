# ADR-0011 Mission 001 Protocol Profile

## Context

Issue #1 (Mission 001) was approved with six open owner decisions: the
cryptographic profile and approved libraries, the normative envelope fields
and canonical encoding, how a recipient trusts a creator's device key, the
payload size bound, the TTL boundary and skew rule, and the carrier's hop
limit and quotas. This ADR records the choices implemented in
`crates/constellation-core` so they can be reviewed as one unit and
revisited before any wire compatibility exists.

## Options Considered

- Crypto: hand-composed X25519 + HKDF + AEAD; HPKE (RFC 9180) base mode;
  age-style sealed boxes; Signal-style ratchets.
- Encoding: canonical JSON; CBOR via `ciborium`; CBOR via `minicbor` with
  integer keys; Protocol Buffers.
- Creator trust: raw device keys in the contact book; user root key plus a
  signed device authorization carried in every envelope; DID documents.
- Size: single bounded blob; chunked manifest from day one.
- TTL: `now > expires_at`; `now >= expires_at`; logical clocks.
- Custody: unbounded store; reject-on-full quotas; priority eviction.

## Decision

1. **Cryptographic profile (suite 1).** Signatures are Ed25519 verified in
   strict mode (`ed25519-dalek`). Payloads use HPKE base mode with
   DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 (`hpke`
   crate, RFC 9180). Hashing is SHA-256 (`sha2`). Every signature and hash
   input carries a `constellation-v1/...` domain prefix. The HPKE AAD binds
   the ciphertext to creator device and audience so it cannot be re-wrapped
   under another envelope. No primitive is implemented in this repository.
2. **Envelope and encoding.** The envelope is CBOR with small unsigned
   integer map keys declared in ascending order (`minicbor`), which yields
   RFC 8949 deterministic encoding without a sort pass. Body fields, in key
   order: version, object type, creator device authorization, created_at,
   expires_at, audience, payload size, payload hash, encryption metadata,
   routing. The signature covers the domain-prefixed canonical body; the
   object id is SHA-256 over the domain-prefixed canonical signed envelope,
   so it commits to the ciphertext hash and never to plaintext. A pinned
   digest test fails on any codec change.
3. **Creator trust.** A user is an Ed25519 root key. Each device has its own
   Ed25519 signing key and X25519 encryption key, authorized by a
   `DeviceAuthorization` signed with the user root key and carried inside
   every envelope. A recipient needs only the creator's *user* key in its
   contact book (the out-of-band trust ceremony); the device is verified
   transitively. Identities are static test-grade: no rotation, revocation
   or recovery exists yet.
4. **Payload bound.** One encrypted blob of at most 64 KiB plaintext
   (65 552 bytes ciphertext). Larger objects wait for the chunk manifest
   work in Mission 012.
5. **Time.** Timestamps are milliseconds since the Unix epoch, UTC. An
   object is expired when `now >= expires_at`. A creator's `created_at`
   may lead the receiver's clock by at most 5 minutes; beyond that the
   object is rejected for clock skew rather than silently accepted.
6. **Custody bounds.** Hop count is transport-local state outside the
   signed envelope; the creator declares `max_hops` and nodes clamp it to
   local policy (default 2, counting the final delivery). Only the creator
   offers custody, only to peers that advertise it and whose user is in its
   contact book, and a carrier accepts custody only from the signed creator at
   hop 1, so there is exactly one custody hop. Acknowledgements release a held
   object only from a peer it was offered to; delivery acks only from the
   audience device. Frames that are not canonically encoded are dropped, and
   known envelope ids are dropped before any verification work. Carrier defaults: 65 552 bytes per object, 8 MiB total,
   256 objects, 32 per handing-over peer; reject-on-full, TTL expiry, no
   priority eviction. Duplicate suppression remembers every accepted,
   delivered or created id for the life of the process.

## Rationale

HPKE is a standardized construction with test vectors, which answers the
"no custom cryptography" gate better than hand-composing primitives, and
its base mode is exactly a sealed box to one device. Integer-keyed CBOR
maps make determinism a property of field declaration order that a single
pinned test can enforce. Carrying the device authorization in the envelope
lets a recipient verify a never-before-seen device offline, which is the
whole point of store-carry-forward. Reject-on-full is the only quota policy
whose behaviour can be fully specified before routing exists.

## Tradeoffs

The `hpke` crate is less widely audited than the dalek and RustCrypto
primitives it composes. Every envelope carries 170 bytes of authorization
overhead. Reject-on-full means a full carrier helps nobody until TTLs expire.
Unbounded duplicate memory is a leak over long uptimes. Only one audience
device per object; multi-device users need Mission 002.

## Security Implications

The carrier verifies the signature and ciphertext hash but holds no key, so
plaintext exposure to B is prevented by construction and asserted by tests.
Peer identifiers in lifecycle events are node-local pseudonyms derived from
the device's secret, never raw ids. The 5-minute skew window is a replay
surface bounded by TTL. Static identities mean a compromised device signs
valid objects indefinitely until revocation exists.

## Reversibility

High until the first physical-device build: version 1 is the only accepted
version, the suite id is explicit, and the pinned-encoding test makes any
silent change fail. Every decision above is one field or one constant.
