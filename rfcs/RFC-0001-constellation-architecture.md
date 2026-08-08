# RFC-0001 Constellation Architecture

## Status

Draft for Mission 001.

## Summary

Constellation is a layered runtime for secure arbitrary object exchange over intermittent and heterogeneous paths. Applications submit objects to the SDK. The runtime signs, encrypts, stores, routes, transfers, verifies, and synchronizes objects through transport adapters.

## Normative Direction

- Applications MUST NOT depend on a specific transport.
- The routing layer MUST see transport capabilities and costs.
- Relays and intermediate carriers MUST NOT need plaintext payload access.
- Store-carry-forward MUST be modeled as explicit custody with bounded TTL, hop limits, quotas, and local policy.
- No central server, account database, discovery service, certificate authority, or relay is mandatory for the base protocol.

## Mission 001 Scope

Mission 001 implements the minimum runtime path for three devices: A creates an encrypted signed object, B receives and stores it, A disappears, B forwards to C, C verifies and decrypts if authorized.

