# Technology Evaluation

Mission 000 evaluated existing systems for reuse, adaptation, or exclusion.

## Summary Matrix

| Technology | Solves | Reuse | Does Not Solve | Coupling Risk | Recommendation |
|---|---|---|---|---|---|
| libp2p | modular P2P transports, peer identity, discovery, multiplexing | transports, protocol negotiation, multiaddr concepts | mobile OS background limits, Constellation object/security semantics, DTN custody | high if it becomes the protocol | ADAPT |
| IPFS/IPLD/UnixFS/CAR | content addressing, Merkle DAGs, chunked files | manifests, chunks, CAR-like transfer bundles | end-to-end audience encryption, mobile DTN routing, identity trust | medium if tied to public IPFS/DHT | ADAPT |
| BitTorrent/WebTorrent | efficient piece exchange and swarming | piece selection and large object transfer ideas | private audience encryption, offline custody, mobile background | medium | ADAPT LATER |
| WebRTC | browser/native P2P media/data, NAT traversal | Internet P2P transport adapter | offline discovery without signaling, store-forward | medium due signaling/TURN expectations | ADAPT |
| Nostr | simple signed event relay protocol | signed event simplicity, relay policy inspiration | E2EE-by-default, mobile offline local transports, DTN routing | medium if social assumptions leak in | STUDY |
| Matrix | federated real-time rooms, state sync, E2EE ecosystem | federation lessons, room/event sync cautionary examples | no-server offline local delivery, transport agnosticism | high if homeserver model dominates | STUDY |
| Signal family | asynchronous E2EE, ratcheting, multi-device session management | X3DH/Double Ratchet/Sesame concepts | routing, decentralized discovery, arbitrary object store | low if used as cryptographic model | REUSE CONCEPTS |
| Noise | authenticated handshakes and secure channels | transport/session handshake patterns | async multi-device object delivery by itself | low | REUSE |
| MLS | group key agreement | future group distribution | disconnected pairwise MVP, routing, discovery | medium complexity | RESEARCH/FUTURE |
| Briar | secure offline messaging via Bluetooth/Wi-Fi/Tor | product proof of local/offline messaging, threat stance | arbitrary app fabric, iOS parity, open SDK target | low | STUDY |
| Meshtastic | LoRa mesh messaging | low-bandwidth mesh/gateway lessons | bulk data/video, phone-native transport | low | FUTURE TRANSPORT |
| BLE Mesh | low-power local mesh | tiny control-plane/rendezvous ideas | bulk transfer, phone background reliability | medium | CONTROL ONLY |
| Wi-Fi Direct | Android local high-bandwidth P2P | Android adapter/spike | iOS public API, universal hardware support | medium | ADAPT ANDROID |
| Apple Multipeer Connectivity | iOS nearby discovery/transfer | iOS Mission 001 adapter | direct control of underlying radio, open protocol semantics | medium | ADAPT IOS |
| Android Nearby Connections | Android/iOS nearby payload transfer API | fast Android MVP adapter | open protocol independence, non-Google environments | high | ADAPT FOR MVP, NOT CORE |
| DTN Bundle Protocol | delay-tolerant bundle semantics | TTL, custody, store-forward concepts | mobile app APIs, app object security | medium complexity | ADAPT CONCEPTS |
| CRDTs | conflict-free replicated state | app-level sync for mutable state | routing, security, large blobs | low | OPTIONAL |

## Sources Consulted

- libp2p docs: https://libp2p.io/docs/
- IPFS docs: https://docs.ipfs.tech/concepts/how-ipfs-works/
- IPFS Merkle DAG docs: https://docs.ipfs.tech/concepts/merkle-dag/
- RFC 9171 Bundle Protocol Version 7: https://www.rfc-editor.org/rfc/rfc9171.html
- Signal X3DH: https://signal.org/docs/specifications/x3dh/
- Signal Double Ratchet: https://signal.org/docs/specifications/doubleratchet/
- Signal Sesame: https://signal.org/docs/specifications/sesame/
- Noise Protocol Framework: https://noiseprotocol.org/
- RFC 9420 MLS: https://www.rfc-editor.org/rfc/rfc9420
- WebRTC W3C Recommendation: https://www.w3.org/TR/webrtc/
- Apple Multipeer Connectivity: https://developer.apple.com/documentation/MultipeerConnectivity
- Android Wi-Fi Direct: https://developer.android.com/develop/connectivity/wifi/wifi-direct
- Nearby Connections: https://developers.google.com/nearby/overview
- Android background limits: https://developer.android.com/about/versions/oreo/background
- Matrix specification: https://spec.matrix.org/
- Nostr NIPs: https://github.com/nostr-protocol/nips
- Briar: https://briarproject.org/how-it-works/

