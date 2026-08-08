# Testing and Observability

## Deterministic Simulation

Constellation should be designed so a simulator can run 100+ virtual nodes with:

- nodes appearing and disappearing;
- network partitions;
- transport failures;
- corrupted messages;
- malicious peers;
- bandwidth and storage limits;
- delayed and duplicate delivery;
- key rotation and revocation;
- device compromise scenarios.

The simulator should use the same object, routing, storage, and transport traits as the runtime, with deterministic clocks and seeded randomness.

## Privacy-Conscious Observability

Diagnostics should cover:

- route selection;
- transport selection;
- object lifecycle;
- synchronization;
- peer connectivity;
- delivery latency;
- failure causes;
- resource consumption.

Logs must not include plaintext payloads, private keys, session secrets, or unnecessary peer relationship metadata. Peer identifiers should be redacted or locally pseudonymized by default.

