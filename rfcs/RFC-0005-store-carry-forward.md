# RFC-0005 Store-Carry-Forward

## Status

Draft.

## Custody

Custody is a node's explicit, local, quota-bound acceptance of responsibility to retain and attempt forwarding of an opaque object until TTL, revocation, eviction, or delivery.

Custody does not guarantee delivery.

## Mission 001

- B accepts custody from A.
- B stores the signed encrypted object.
- B later discovers C.
- B forwards the object to C.
- C verifies creator signature, payload integrity, TTL, and recipient authorization.
- C decrypts only if authorized.

## Anti-Flooding

Forwarding must enforce TTL, hop limit, duplicate suppression, size limits, and per-peer quotas.

