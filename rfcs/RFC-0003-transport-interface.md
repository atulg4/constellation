# RFC-0003 Transport Interface

## Status

Draft.

## Interface

Transport adapters expose discovery, advertising, connection, send/receive, close, metrics, and capability reporting.

## Capability Requirements

Adapters MUST report:

- bandwidth class;
- latency class;
- range/locality;
- cost and metering risk;
- energy class;
- max payload/frame size;
- reliability;
- background viability;
- discovery/advertising support;
- permissions required;
- platform constraints;
- link-authentication capabilities.

Routing MUST treat reported capabilities as hints, not guarantees.

## Mission 001 Adapters

Use foreground local adapters only. Candidate adapters: iOS Multipeer Connectivity, Android Nearby Connections, and shared-LAN TCP/QUIC.

