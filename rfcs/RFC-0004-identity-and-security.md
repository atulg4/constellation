# RFC-0004 Identity and Security

## Status

Draft.

## Principles

- User, device, organization, relay, and pseudonymous identities are separate principals.
- Device authorization is explicit and signed.
- Contact verification is required for strong authentication.
- Revocation is eventual under partition.
- Use established protocols and primitives only.

## Mission 001 Security

Mission 001 MUST implement:

- signed creator/device identity;
- canonical envelope signatures;
- per-object encryption for authorized recipient device(s);
- ciphertext integrity verification;
- replay/duplicate detection;
- TTL enforcement;
- no plaintext exposure to carriers.

Mission 001 MAY use simplified static test identities if the limitation is documented and not presented as production identity.

