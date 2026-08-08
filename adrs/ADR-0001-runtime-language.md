# ADR-0001 Runtime Language

## Context

Constellation needs a portable runtime suitable for cryptography, networking, storage, deterministic simulation, mobile bindings, desktop/server nodes, and constrained devices.

## Options Considered

- Rust core with Kotlin/Swift/desktop bindings.
- Kotlin Multiplatform.
- Swift plus Kotlin native implementations.
- Go core.
- C/C++ core.

## Decision

Use Rust as the default candidate for the protocol/runtime core in Mission 001 spikes, while keeping the wire protocol and object formats implementation-independent.

## Rationale

Rust offers memory safety, strong crypto/networking ecosystems, good performance, C-compatible FFI, growing mobile binding support, and deterministic test ergonomics. Kotlin Multiplatform and Swift are strong for app layers but less suitable as a single systems core across relay/server/mobile. Go is productive but has mobile/binary-size and FFI tradeoffs. C/C++ has ecosystem reach but imposes unnecessary memory-safety risk.

## Tradeoffs

Rust increases learning curve and FFI complexity. Mobile packaging must be validated early.

## Security Implications

Memory safety is important for parsers, crypto-adjacent code, and hostile inputs. Rust does not remove protocol design risk.

## Reversibility

Moderate. Keep protocol schemas, tests, and simulator contracts language-neutral so another implementation can replace the Rust core if mobile constraints prove unacceptable.

