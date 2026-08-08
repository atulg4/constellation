# Transport Abstraction

The transport abstraction hides mechanics from applications while exposing enough truth for routing decisions.

## Candidate Interface

```text
Transport
  id()
  capabilities()
  discover(scope, filters)
  advertise(descriptor, policy)
  connect(peer_hint, policy)
  send(connection, frame)
  receive(connection)
  close(connection)
  cost()
  availability()
  metrics()
```

## Required Capability Dimensions

- range/locality
- expected bandwidth
- latency class
- connection setup cost
- energy class
- metered monetary/data cost
- max frame/payload size
- reliability support
- bidirectionality
- discovery support
- multicast/broadcast support
- background viability
- OS permission requirements
- peer authentication hooks
- confidentiality provided by transport
- NAT traversal needs

## Mission 001 Transport Position

Use one native local transport per platform where practical:

- Android: prefer Nearby Connections for the first demo if available; evaluate raw Wi-Fi Direct as a fallback or later transport.
- iOS: prefer Multipeer Connectivity for the first iOS-local demo.
- Cross-platform desktop simulation: use LAN/TCP or QUIC behind the same transport interface.

The Constellation security layer must remain end-to-end even if a platform transport also encrypts links.

