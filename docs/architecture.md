# Architecture

Constellation is a layered runtime and protocol suite:

```text
Applications
Constellation SDK
Object Envelope Layer
Security and Identity Layer
Routing and Synchronization Layer
Local Content Store
Transport Abstraction Layer
Wi-Fi P2P | LAN | BLE | QUIC | WebRTC | Relay | Future Transports
```

## Runtime Roles

The same runtime should support multiple node profiles:

- Mobile node: originates, consumes, caches, carries, and selectively relays data under strict OS/resource limits.
- Desktop node: higher availability and storage, good for simulation, development, and local gateway behavior.
- Community relay: low-cost always-on node that stores, discovers, and relays opaque encrypted objects.
- Gateway: bridges network domains, such as LAN to Internet or local mesh to satellite uplink.
- Cloud relay: optional Internet-facing node that improves availability but is not mandatory.

## Object Flow

1. Application submits a typed object, audience, priority, TTL, and replication policy.
2. SDK builds a signed envelope and encrypts payload material for authorized recipients.
3. Object store chunks large payloads into content-addressed blocks and records a manifest.
4. Router selects feasible transports based on policy, capability, contact opportunity, and resource budgets.
5. Receiving node verifies envelope signature, object hash, manifest/chunk integrity, replay constraints, and authorization metadata.
6. A node may accept custody for later forwarding if local policy permits it.
7. Delivery receipts and custody acknowledgements are separate signed control objects.

## Key Design Position

Constellation should reuse or adapt mature components, but the durable protocol boundary is the object, identity, security, storage, routing, and transport-contract semantics. No single implementation library should become the protocol.

