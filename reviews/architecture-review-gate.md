# Architecture Review Gate

Question:

> Are we building something that already exists?

## Assessment

Constellation shares concepts with libp2p, IPFS, DTN, Signal, Briar, Matrix, Nostr, WebRTC, and platform local-network APIs. None fully satisfies the required combination:

- arbitrary application objects;
- end-to-end object security;
- offline/local-first operation;
- store-carry-forward;
- transport abstraction across local, P2P, relay, gateway, and future paths;
- no mandatory global server/account/CA;
- mobile-aware resource and platform constraints;
- open protocol and SDK target.

## Gate Result

Proceed to Mission 001 with a narrow prototype. Revisit reuse/adapt/build before implementing each subsystem. Do not implement a social network, global relay network, or production cryptographic protocol in Mission 001.

