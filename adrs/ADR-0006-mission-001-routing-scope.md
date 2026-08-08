# ADR-0006 Mission 001 Routing Scope

## Context

The long-term routing model includes opportunistic, multipath, relay, and gateway delivery. Implementing that immediately would obscure the first proof.

## Options Considered

- Implement multipath routing in Mission 001.
- Implement epidemic gossip in Mission 001.
- Implement direct plus one-hop custody forwarding.

## Decision

Mission 001 implements direct delivery and one-hop custody forwarding only.

## Rationale

The first milestone must prove secure store-carry-forward without a server. Multipath and gossip introduce abuse, metadata, and debugging complexity before the core object/security/storage path is proven.

## Tradeoffs

The demo will not show large-scale routing or robust multi-hop delivery.

## Security Implications

Narrow scope reduces DoS and metadata risks. It also prevents making unsupported claims about delivery reliability.

## Reversibility

High. Later missions can add routing strategies behind the same routing interface.

