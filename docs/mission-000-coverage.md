# Mission 000 Coverage

## Success Criteria Answers

1. What is Constellation? See `docs/vision.md` and `docs/architecture.md`.
2. What problem does it solve? Secure object exchange over intermittent heterogeneous paths.
3. What does it not solve? No magical connectivity, no perfect anonymity, no mandatory social product.
4. How does an object travel? See `docs/architecture.md`, `docs/object-model.md`, and `docs/routing.md`.
5. How are identities represented? See `docs/identity-model.md`.
6. How is content protected? See `docs/security-model.md`.
7. How are peers discovered? Through transport adapters; see `docs/transport-abstraction.md` and `docs/platform-constraints.md`.
8. How do transports plug in? See `rfcs/RFC-0003-transport-interface.md`.
9. What happens without Internet? Local transports and store-carry-forward remain possible when a physical path exists.
10. What happens during a partition? Delivery is delayed, custody may continue, and status may remain unknown until contact resumes.
11. How does store-carry-forward work? See `rfcs/RFC-0005-store-carry-forward.md`.
12. How are large files/videos represented? Encrypted manifests and content-addressed chunks.
13. What existing technologies are reused? See `docs/research/technology-evaluation.md`.
14. Why were technologies selected? See ADRs and `docs/research/reuse-adapt-build.md`.
15. What are the major threats? See `docs/threat-model.md`.
16. What are Android/iOS limitations? See `docs/platform-constraints.md`.
17. What is Mission 001? See `missions/001-core-runtime.md`.
18. What must be demonstrated before progressing? Three-device authenticated encrypted store-carry-forward delivery without a central server.

