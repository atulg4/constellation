# ADR-0007 Mobile MVP Transports

## Context

Mission 001 targets three physical devices with no Internet. Mobile OS APIs impose hard constraints.

## Options Considered

- Raw Wi-Fi Direct on all platforms.
- BLE-only transfer.
- iOS Multipeer Connectivity, Android Nearby Connections, shared-LAN fallback.
- Build custom radio stack.

## Decision

Use platform local transport adapters: iOS Multipeer Connectivity, Android Nearby Connections for MVP speed, and shared-LAN discovery/transfer for desktop/cross-platform testing. BLE is discovery/control-plane only.

## Rationale

iOS lacks public raw Wi-Fi Direct APIs. Android Wi-Fi Direct is available but OEM/permission sensitive. BLE is not appropriate for file/video transfer. Platform adapters keep Mission 001 feasible while preserving the Constellation protocol boundary.

## Tradeoffs

Nearby Connections creates Google Play Services coupling for Android MVP. Multipeer hides underlying radio choice from the app.

## Security Implications

Platform link encryption is not trusted as end-to-end object security. The Constellation layer still authenticates and encrypts objects.

## Reversibility

High if these are transport adapters with explicit capabilities.

