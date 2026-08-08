# ADR-0002 libp2p Adaptation

## Context

libp2p provides modular P2P networking, transports, peer IDs, discovery, multiplexing, and protocol negotiation.

## Options Considered

- Adopt libp2p as the Constellation protocol/runtime.
- Use libp2p as one implementation substrate where it fits.
- Avoid libp2p entirely.

## Decision

Adapt libp2p concepts and possibly use libp2p adapters for desktop/server/Internet transports, but do not define Constellation as libp2p.

## Rationale

Constellation must survive mobile platform constraints, offline custody semantics, and future transport adapters that libp2p may not model well. The durable protocol boundary is object, identity, storage, security, routing, and transport capability semantics.

## Tradeoffs

This avoids premature coupling but may delay reuse of mature libp2p components.

## Security Implications

libp2p secure channels do not replace Constellation end-to-end object encryption. Peer identity must be bound carefully to Constellation identities.

## Reversibility

High if libp2p remains behind transport/runtime adapters.

