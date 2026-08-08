# Agent Perspectives

Mission 000 incorporated independent role reviews.

## Distributed Systems / Routing

- DTN/store-carry-forward must be first-class.
- Custody should be explicit and policy-bound.
- Transports need operational capability metadata.
- libp2p may accelerate some implementations but must not become the whole protocol.
- Mission 001 should use direct delivery plus one-hop custody only.

## Applied Cryptography / Security

- User, device, and organization identities are separate principals.
- A single long-term keypair is insufficient.
- Content IDs must not be raw plaintext hashes.
- Signatures must cover canonical envelope metadata and payload/manifest hashes.
- Revocation is eventual across partitions.
- Avoid claims such as anonymous, unblockable, metadata-private, or immediate revocation.

## Mobile Platform / Networking

- Phones are opportunistic carriers, not reliable always-on mesh routers.
- iOS has no public raw Wi-Fi Direct API; use Multipeer Connectivity for iOS MVP.
- Android Wi-Fi Direct is real but permission/OEM dependent.
- Android Nearby Connections is useful for MVP speed but creates platform coupling.
- BLE is appropriate for discovery/control, not video-scale transfer.
- Mission 001 should be foreground, permission-explicit, and manually choreographed.

