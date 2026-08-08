# Threat Model

## Defend Against

- message tampering through signatures and content hashes;
- unauthorized content reads through end-to-end encryption;
- compromised relay reading plaintext;
- basic replay through object IDs, timestamps, nonces, session state, and replay windows;
- malicious content injection through schema validation, signatures, audience checks, and quotas;
- accidental corruption through chunk and manifest verification;
- impersonation after contact verification by binding identities to verified keys.

## Partially Mitigate

- passive traffic analysis through local-first routing, batching, padding, reduced logs, and relay minimization;
- Sybil attacks through trust scopes, quotas, proof-of-work/rate policies where appropriate, and application-level trust;
- denial of service through quotas, backpressure, admission controls, and bounded parsing;
- eclipse attacks through diverse discovery sources and transport diversity;
- malicious routing through signed receipts, duplicate suppression, hop limits, and conservative custody policy;
- key compromise through rotation, revocation, session expiration, and device replacement flows;
- rollback attacks through signed monotonic key-state objects where a peer has enough history.

## Cannot Fundamentally Defend Against

- no physical communication path;
- compromised endpoint reading its own plaintext;
- global passive adversary learning some timing/contact information in many deployments;
- delayed revocation in disconnected partitions;
- recipients copying decrypted content;
- malicious OS or hardware below the application trust boundary;
- legal or app-store restrictions that prevent transport use.

## One-Million Hostile Device Attack Review

Likely attacks:

- flood relays and mobile nodes with valid-looking junk;
- create many identities to exhaust discovery/routing tables;
- publish malicious manifests with huge fan-out;
- exploit parser bugs in envelopes/manifests;
- replay old key-transition objects;
- collect metadata by operating popular relays;
- poison routing hints;
- force expensive cryptographic verification loops;
- abuse protocol upgrade negotiation;
- use compromised devices as trusted signers.

Mission 001 must therefore keep parsing bounded, schemas strict, quotas small, and routing simple.

