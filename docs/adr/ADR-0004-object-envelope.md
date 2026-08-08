# ADR-0004 Object Envelope

## Context

Constellation carries arbitrary application objects and control records across untrusted transports and relays.

## Options Considered

- Chat-message schema.
- Nostr-like signed event schema.
- Matrix-like room events.
- Constellation-specific signed envelope.

## Decision

Define a Constellation-specific canonical signed envelope with typed object metadata, audience, payload reference, TTL, routing/replication policy, encryption metadata, and signature.

## Rationale

Chat/social schemas are too narrow. Existing event systems are useful references but do not encode Constellation's transport-agnostic custody and resource policy needs.

## Tradeoffs

New schema requires specification and conformance tests.

## Security Implications

Signatures must cover canonical metadata and payload/manifest hashes. Algorithm metadata must be versioned and downgrade-resistant.

## Reversibility

Moderate. Versioned envelopes allow future schema evolution.

