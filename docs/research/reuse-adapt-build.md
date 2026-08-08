# Reuse, Adapt, Build Classification

## REUSE

- reviewed cryptographic primitives and libraries;
- Noise framework patterns for authenticated transport sessions;
- Signal-family concepts for asynchronous pairwise sessions and multi-device session management;
- standard AEAD, HKDF, X25519/Ed25519 or equivalent reviewed schemes;
- platform APIs where the OS requires them.

## ADAPT

- libp2p transport and peer-addressing concepts;
- IPFS/IPLD/Merkle-DAG/CAR content-addressing concepts;
- DTN Bundle Protocol TTL/custody/store-forward concepts;
- WebRTC as an Internet P2P transport;
- Matrix/Nostr lessons for signed events, relays, federation, and failure modes;
- CRDTs for specific application state models;
- BitTorrent piece exchange ideas for later large-object transfer.

## BUILD

- Constellation object envelope;
- Constellation identity/key-transition model;
- end-to-end object encryption/wrapping policy;
- local resource-aware routing and custody policy;
- mobile-aware transport capability abstraction;
- deterministic simulator;
- SDK submission and delivery-state API;
- abuse controls tied to quotas, trust scope, and local policy.

## Architecture Review Conclusion

Constellation overlaps with existing systems but is not identical to any single one. Its value is the integration layer for secure arbitrary objects over intermittent local, peer, relay, and future transports without mandatory central infrastructure.

The strongest risk is accidentally rebuilding existing systems badly. The mitigation is to keep reuse/adapt/build decisions explicit in ADRs and revisit them before each implementation mission.

