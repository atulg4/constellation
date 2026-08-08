# ADR-0008 DTN Custody Semantics

## Context

Store-carry-forward requires nodes to hold encrypted objects for later delivery.

## Options Considered

- Best-effort cache only.
- Epidemic replication.
- Explicit custody acceptance with TTL, quotas, and receipts.

## Decision

Model custody as explicit local acceptance of bounded responsibility for an opaque object or chunk set, governed by TTL, hop limits, quotas, priority, audience, and local trust policy.

## Rationale

Explicit custody makes delayed delivery observable and resource-bounded. Epidemic replication is too expensive and abuse-prone as a default.

## Tradeoffs

Custody does not guarantee delivery. Nodes may reject custody.

## Security Implications

Custody receipts must be signed and must not imply plaintext access or global delivery guarantee.

## Reversibility

Moderate. Later routing algorithms can use the same custody primitive.

