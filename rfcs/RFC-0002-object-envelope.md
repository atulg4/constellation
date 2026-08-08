# RFC-0002 Object Envelope

## Status

Draft.

## Envelope Requirements

An envelope MUST be canonical, immutable, signed, versioned, and independently verifiable.

Required fields for Mission 001:

- version;
- object ID;
- object type;
- creator identity;
- creator device;
- creation logical time and best-effort wall time;
- expiration/TTL;
- audience;
- payload reference or inline payload;
- payload/manifest hash;
- encryption metadata;
- routing policy;
- signature.

Payload hashes MUST NOT reveal plaintext content. Hash ciphertext or use a protected commitment profile.

## Control Objects

Delivery receipts, custody receipts, key updates, revocations, and protocol upgrades use the same envelope discipline with restricted schemas.

