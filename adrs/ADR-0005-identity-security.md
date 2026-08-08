# ADR-0005 Identity and Security Model

## Context

Constellation cannot assume central accounts, phone numbers, email addresses, DNS, or a global CA.

## Options Considered

- Single public/private key per user.
- Central account server.
- DID-like user identity with authorized device keys.
- Enterprise CA only.

## Decision

Use decentralized cryptographic identities with separate user, device, organization, relay, and pseudonymous principals. Devices are authorized by signed identity state. Enterprise identity is optional and layered.

## Rationale

Multi-device use, migration, rotation, and revocation require more than a single static key. Central account infrastructure violates the base protocol goal.

## Tradeoffs

Identity state and revocation become complex, especially offline.

## Security Implications

First-contact authentication still needs a trust ceremony. Offline revocation is eventual. Compromised devices remain dangerous until peers receive revocation.

## Reversibility

Moderate. Identity documents and key-transition records must be versioned.

