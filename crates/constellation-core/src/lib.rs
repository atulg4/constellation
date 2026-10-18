//! Constellation core runtime, Mission 001.
//!
//! Proves authenticated, encrypted, integrity-verified, one-hop
//! store-carry-forward delivery across three devices with no server:
//!
//! ```text
//! A creates an encrypted, signed object for C
//! A -> B over a local transport; B keeps custody of opaque bytes
//! A disappears
//! B -> C later; C verifies the envelope and decrypts
//! ```
//!
//! Module map:
//! - [`identity`]: user and device keys, signed device authorization, contact trust.
//! - [`envelope`]: canonical signed envelope, object ids, wire frames.
//! - [`crypto`]: HPKE payload sealing and SHA-256 helpers (no custom primitives).
//! - [`store`]: bounded in-memory custody store with quotas and TTL expiry.
//! - [`node`]: the validation pipeline, custody policy, and privacy-safe events.
//! - [`transport`]: the adapter contract that platform transports will implement.
//! - [`sim`]: deterministic in-process network for the A/B/C scenarios.
//!
//! Normative decisions for this profile live in
//! `docs/adr/ADR-0011-mission-001-protocol-profile.md`.

/// Defines a fixed-size byte newtype that encodes as a CBOR byte string.
macro_rules! fixed_bytes {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Borrows the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8; $len]> for $name {
            fn from(bytes: &[u8; $len]) -> Self {
                Self(*bytes)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for b in &self.0[..4] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "…)")
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                e: &mut minicbor::Encoder<W>,
                _: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                e.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'b, C> minicbor::Decode<'b, C> for $name {
            fn decode(
                d: &mut minicbor::Decoder<'b>,
                _: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let raw = d.bytes()?;
                let arr: [u8; $len] = raw.try_into().map_err(|_| {
                    minicbor::decode::Error::message(concat!(
                        "expected ",
                        stringify!($len),
                        " bytes for ",
                        stringify!($name)
                    ))
                })?;
                Ok(Self(arr))
            }
        }
    };
}

pub mod crypto;
pub mod envelope;
pub mod identity;
pub mod node;
pub mod sim;
pub mod store;
pub mod transport;

/// Milliseconds since the Unix epoch, UTC. Never compared across trust
/// boundaries without the skew allowance in [`node::Policy`].
pub type Timestamp = u64;

/// Wire protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u8 = 1;

/// Largest plaintext a Mission 001 object may carry (one bounded blob).
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;

/// AEAD authentication tag length for the only supported suite.
pub const AEAD_TAG_BYTES: usize = 16;

/// Largest ciphertext a node will decode or store.
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + AEAD_TAG_BYTES;

/// Largest encoded frame a node will decode; the rest is envelope overhead.
pub const MAX_FRAME_BYTES: usize = MAX_CIPHERTEXT_BYTES + 1024;

/// Domain-separation strings. Every signature and hash in this profile
/// is prefixed with one so values can never be confused across contexts.
pub mod domain {
    /// Prefix for the envelope signature input.
    pub const ENVELOPE_SIGNATURE: &[u8] = b"constellation-v1/envelope-signature";
    /// Prefix for object-id derivation.
    pub const OBJECT_ID: &[u8] = b"constellation-v1/object-id";
    /// Prefix for the device-authorization signature input.
    pub const DEVICE_AUTHORIZATION: &[u8] = b"constellation-v1/device-authorization";
    /// HPKE `info` for payload encryption.
    pub const PAYLOAD_INFO: &[u8] = b"constellation-v1/payload";
    /// Prefix for the payload AAD binding ciphertext to creator and audience.
    pub const PAYLOAD_AAD: &[u8] = b"constellation-v1/payload-aad";
    /// Prefix for node-local peer pseudonyms in events.
    pub const PEER_TAG: &[u8] = b"constellation-v1/peer-tag";
}
