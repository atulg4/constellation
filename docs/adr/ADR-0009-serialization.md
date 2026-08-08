# ADR-0009 Serialization

## Context

Signed envelopes require deterministic canonical serialization across independent implementations.

## Options Considered

- JSON.
- Canonical JSON.
- CBOR with deterministic encoding.
- Protocol Buffers.

## Decision

Use deterministic CBOR as the leading candidate for signed protocol objects, with JSON diagnostic forms for docs and tests.

## Rationale

CBOR is compact, binary-friendly, and can be deterministically encoded. JSON is easy to debug but canonicalization is fragile. Protocol Buffers are efficient but canonical signing and unknown-field behavior need extra care.

## Tradeoffs

CBOR is less human-readable and requires strict canonical profile tests.

## Security Implications

Ambiguous serialization breaks signatures and can enable downgrade or parser-differential attacks.

## Reversibility

Moderate before implementation, lower after wire compatibility exists.

