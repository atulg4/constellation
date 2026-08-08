# Platform Constraints

Mobile platforms are the largest feasibility constraint.

## Android

Android supports Wi-Fi Direct APIs, but apps need permissions such as Wi-Fi state, change Wi-Fi state, Internet for sockets, location or nearby Wi-Fi permissions depending on API level, and location mode for peer discovery. Not all devices support Wi-Fi Direct.

Nearby Connections provides an easier offline P2P abstraction using Bluetooth, Wi-Fi, and related technologies, with strategies for point-to-point, star, and cluster topologies. It depends on Google Play services availability and creates platform coupling.

Android background execution limits restrict long-running background services. Opportunistic relay behavior should use foreground services only when user-visible and acceptable, WorkManager/jobs where appropriate, and explicit user controls.

## iOS

Multipeer Connectivity supports nearby discovery and communication using infrastructure Wi-Fi, peer-to-peer Wi-Fi, and Bluetooth personal area networking. Apps must declare local network and Bonjour usage keys.

iOS background execution is restrictive. Mission 001 should assume foreground or user-visible testing. Always-on background store-carry-forward on ordinary iOS apps is not a safe architectural assumption.

## MVP Reality

Mission 001 should be designed as a foreground three-device demonstration. Background relaying, passive always-on discovery, and cross-platform mobile parity should be later gated work.

