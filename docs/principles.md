# Principles

1. Offline first: useful communication between nearby devices must be possible with no Internet.
2. Local first: local communication should remain local when policy and delivery goals allow it.
3. Transport agnostic, not transport blind: applications should not depend on a transport, but routing must understand each transport's cost, range, bandwidth, latency, energy, background viability, and trust implications.
4. Store-carry-forward: disconnected delivery is a first-class mode, not an exceptional retry path.
5. No mandatory central authority: central services may improve availability but must not be required by the base protocol where direct/local paths exist.
6. Strong security: use established cryptographic protocols and primitives. Do not invent custom cryptography.
7. Content addressed data: immutable payloads and chunks should be cryptographically identified and independently verifiable.
8. Resource awareness: devices must control bandwidth, storage, battery, thermal, cellular, and relay participation budgets.
9. Privacy by architecture: distinguish content confidentiality from metadata exposure and avoid anonymity claims that cannot be defended.
10. Open protocol: the base protocol should support independent implementations.

