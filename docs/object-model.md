# Object Model

Constellation carries arbitrary typed objects, not chat-specific messages.

## Envelope

An envelope is immutable and signed. Payload bytes may be inline only for very small objects; normal payloads are referenced by encrypted manifests and content-addressed chunks.

Candidate fields:

- `version`
- `object_id`
- `object_type`
- `creator_identity`
- `creator_device`
- `created_at`
- `expires_at`
- `audience`
- `payload_ref`
- `payload_size`
- `content_hash`
- `encryption`
- `signature`
- `routing_hints`
- `replication_policy`
- `priority`
- `delivery_requirements`
- `previous_refs`
- `app_metadata`

## Object ID

`object_id` should be derived from a canonical encoding of the signed envelope excluding transport-local state. Mutable application state should be modeled as new immutable events that reference earlier objects.

## Large Objects

Large files and videos use:

```text
Envelope -> encrypted manifest -> content-addressed encrypted chunks
```

Chunks are independently transferable and verifiable. The manifest records chunk hashes, sizes, ordering, encryption parameters, and reconstruction metadata.

## Control Objects

Delivery receipts, custody acknowledgements, revocations, key updates, and protocol upgrade notices are also signed objects with constrained schemas.

