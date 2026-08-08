# ADR-0010 Simulator-First Testing

## Context

Intermittent networks, malicious peers, resource exhaustion, and offline key changes are hard to test only with devices.

## Options Considered

- Device-only manual tests.
- Unit tests only.
- Deterministic simulator plus device smoke tests.

## Decision

Build routing, storage, and transport interfaces so deterministic simulation is possible from the beginning.

## Rationale

Simulation is required to test partitions, delays, duplicates, malicious peers, and 100+ node scenarios without unreliable manual setup.

## Tradeoffs

Abstractions must be designed earlier and kept honest with real device tests.

## Security Implications

Simulator scenarios must include hostile-majority and resource-exhaustion cases, not only happy paths.

## Reversibility

Low. Retrofitting simulation later is expensive.

