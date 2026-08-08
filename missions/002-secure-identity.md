# Mission 002 - Secure Identity

## Summary

Implement decentralized user/device identity, device authorization, contact verification, key rotation, and eventual revocation primitives.

## Acceptance Criteria

- [ ] User and device identities are separate principals.
- [ ] Device addition requires an authenticated ceremony.
- [ ] Revocation and rotation are signed, versioned, and replay-resistant.
- [ ] Contact verification UX/API is specified.

## Required Tests

- Device add/remove tests.
- Key rotation and rollback tests.
- Offline delayed revocation simulation.

## Non-Goals

- Mandatory phone/email identity.
- Global CA.
- Enterprise-only identity.

## Dependencies

Mission 001.

