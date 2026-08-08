# Mission 012 - Large Object and Video

## Summary

Extend object manifests and chunk transfer for moderately sized files/videos.

## Acceptance Criteria

- [ ] Large payloads are chunked and verifiable.
- [ ] Partial transfer can resume.
- [ ] Size metadata leakage is documented and mitigated where practical.

## Required Tests

- Chunk corruption tests.
- Resume tests.
- Quota and eviction tests.

## Non-Goals

- Streaming platform.
- Recommendation algorithms.

## Dependencies

Missions 004 and 009.

