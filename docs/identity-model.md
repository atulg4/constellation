# Identity Model

Identity is decentralized and cryptographic. Phone numbers, email addresses, DNS names, and enterprise directories may be optional discovery or verification aids, but must not be mandatory global identifiers.

## Entities

- user identity;
- device identity;
- organization identity;
- pseudonymous identity;
- relay/gateway identity;
- application namespace identity.

## Candidate Model

- User identity is rooted in a long-term public key or DID-like document.
- Each device has a device key signed or authorized by the user identity.
- Contacts verify identities through QR scan, fingerprint comparison, local introduction, organizational policy, or trusted out-of-band channels.
- Lost devices are revoked by publishing signed revocation objects.
- Key rotation is represented as signed key-transition objects.
- Enterprise identity can bind organizational credentials to Constellation identities without replacing the open base model.

## Open Issues

- Offline revocation propagation is inherently delayed.
- First-contact authentication is unsolved without an out-of-band trust path.
- Multi-device state must avoid relying on a central account server.
- Compromised devices may sign valid objects until revocation reaches peers.

