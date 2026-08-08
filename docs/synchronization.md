# Synchronization

Constellation should support multiple application consistency models rather than forcing all apps into chat-style ordered streams.

## Base Synchronization

- immutable object reconciliation by object ID;
- manifest/chunk availability exchange;
- signed control objects for delivery/custody/key updates;
- vector or version summaries for bounded sync;
- application namespace separation.

## Application-Level Options

- append-only event logs for messaging and audit-like workflows;
- DAGs for causal object histories;
- CRDTs for collaborative mutable state;
- explicit conflict objects where human resolution is required;
- manifests for file/video reconstruction.

## Constraints

Peers may reconnect after minutes, hours, or days. Sync must tolerate duplicates, missing chunks, expired objects, partial transfer, revoked identities, and conflicting offline edits.

