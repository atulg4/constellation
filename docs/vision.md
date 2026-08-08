# Vision

Constellation is a reusable communication fabric for applications and devices that need to exchange arbitrary data across intermittent, heterogeneous, potentially hostile connectivity.

It is not a messaging app, social network, cloud relay, or single transport stack. Those can be built on top of it.

The guiding question is:

> How can two applications securely exchange data when connectivity is intermittent, heterogeneous, potentially hostile, and outside the control of any single infrastructure provider?

Constellation should let an application submit an object and desired audience without knowing whether delivery happens through Wi-Fi Direct, LAN, Bluetooth/BLE, Internet QUIC, WebRTC, fixed relays, community mesh, satellite gateway, physical device movement, or a combination of those paths.

## Physical Boundary

No protocol can communicate across a physical partition when no communication path exists. If there is no Internet, radio path, satellite path, mesh path, relay path, or physical movement of devices/media, immediate communication is impossible.

Constellation exploits available paths and tolerates temporary absence of paths. It does not create connectivity where physics provides none.

