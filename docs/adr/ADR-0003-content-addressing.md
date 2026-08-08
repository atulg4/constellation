# ADR-0003 Content Addressing

## Context

Constellation needs verifiable transfer of arbitrary payloads and large files/videos over partial, delayed paths.

## Options Considered

- Reuse public IPFS/IPLD/UnixFS directly.
- Define Constellation manifests using IPFS/IPLD/CAR-compatible concepts.
- Build a fully custom chunking system.

## Decision

Use content-addressed encrypted chunks and manifests inspired by IPFS/IPLD/CAR, but do not depend on the public IPFS network, DHT, or default UnixFS profiles in Mission 001.

## Rationale

Merkle structures and content addressing are mature. Constellation needs audience encryption, deterministic profiles, mobile quotas, and store-carry-forward policy that public IPFS does not provide by itself.

## Tradeoffs

Partial compatibility requires careful profile definition. Direct IPFS tooling reuse may be limited initially.

## Security Implications

Content IDs must be over ciphertext or protected commitments, not raw plaintext hashes, to avoid content-leakage attacks.

## Reversibility

Moderate. Manifests can later gain IPLD/CAR compatibility if canonical profiles are chosen.

