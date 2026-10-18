//! The transport adapter contract (RFC-0003, Mission 001 subset).
//!
//! Platform adapters (iOS Multipeer Connectivity, Android Nearby
//! Connections, LAN TCP/QUIC) will implement [`Transport`] in later work.
//! The core never trusts link encryption: every object stays end-to-end
//! protected by its envelope regardless of what the adapter reports.

use crate::envelope::Frame;
use crate::identity::DeviceId;

/// How far a transport reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locality {
    /// Radio proximity: BLE, Wi-Fi Aware, Multipeer, Nearby.
    Proximity,
    /// Shared local network.
    LocalNetwork,
    /// Routed Internet path.
    Internet,
    /// In-process simulation.
    Simulated,
}

/// Capability hints a router may use. Hints, never guarantees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Human-readable adapter name.
    pub name: &'static str,
    /// Reach.
    pub locality: Locality,
    /// Largest frame the adapter will carry.
    pub max_frame_bytes: usize,
    /// Whether the OS lets this adapter run without a foreground UI.
    pub background_viable: bool,
    /// Whether the link itself is encrypted (informational only).
    pub link_encrypted: bool,
}

/// Errors an adapter may report.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// No live link to the peer.
    #[error("peer not reachable")]
    Unreachable,
    /// The frame exceeds the adapter's limit.
    #[error("frame exceeds transport limit")]
    FrameTooLarge,
}

/// A foreground, point-to-point adapter bound to one local device.
pub trait Transport {
    /// Static capability report.
    fn capabilities(&self) -> Capabilities;
    /// Sends one frame to a peer currently in contact.
    fn send(&mut self, to: &DeviceId, frame: &Frame) -> Result<(), TransportError>;
    /// Takes the next received frame and its sender, if any.
    fn poll(&mut self) -> Option<(DeviceId, Frame)>;
}
