# Security Model

Constellation assumes hostile networks, malicious peers, compromised relays, and intermittent connectivity.

## Baseline Goals

- end-to-end confidentiality for payloads;
- creator authenticity for signed envelopes;
- integrity for envelopes, manifests, and chunks;
- replay detection within feasible storage windows;
- forward secrecy where interactive sessions are available;
- post-compromise recovery where ratcheting protocols support it;
- key rotation and revocation objects;
- least metadata exposure practical for the delivery mode.

## Cryptographic Position

Constellation must not invent cryptographic primitives. It should reuse:

- Noise patterns for authenticated channel/session handshakes where appropriate;
- Signal protocol family concepts for asynchronous pairwise encrypted messaging;
- MLS for group-keying research and future group distribution;
- AEADs, HKDFs, signature schemes, and hashes from reviewed libraries.

Transport encryption is not sufficient. Relays and intermediate carriers must not need plaintext access.

## Non-Claims

Constellation does not guarantee perfect anonymity, unblockability, prompt delivery, deletion after dissemination, or safety after unrevoked device compromise.

