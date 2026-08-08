# Storage

Each node maintains a local encrypted content store with explicit quotas and garbage collection.

## Store Contents

- signed envelopes;
- encrypted manifests;
- encrypted chunks;
- key/session state;
- peer/contact metadata;
- delivery/custody receipts;
- routing hints and local metrics;
- audit/debug logs with privacy controls.

## Properties

- immutable object storage;
- content-addressed payload blocks;
- deduplication for identical encrypted chunks where safe;
- TTL and retention policies;
- per-identity and per-peer quotas;
- encrypted-at-rest storage;
- priority-aware eviction;
- explicit relay participation controls;
- corruption detection via hash verification.

Nodes do not retain every object they encounter. Relaying is governed by local policy, trust, quota, object TTL, audience, and abuse controls.

