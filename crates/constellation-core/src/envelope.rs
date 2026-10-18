//! The canonical signed envelope and the wire frames that carry it.
//!
//! Encoding is CBOR with small unsigned-integer map keys declared in
//! ascending order, so the derive emits RFC 8949 deterministic encoding
//! without a sorting pass. Fixtures in the tests pin the exact bytes.
//!
//! The signature covers the domain-separated canonical body. The object id
//! is SHA-256 over the domain-separated canonical *signed* envelope, so it
//! commits to the ciphertext hash and never to plaintext. Transport-local
//! custody state (hop count, who handed it over) lives outside the envelope.

use minicbor::{Decode, Encode};

use crate::crypto::{sha256, Hash};
use crate::identity::{
    verify, DeviceAuthorization, DeviceId, DeviceIdentity, EncryptionKey, IdentityError, Sig,
    UserId,
};
use crate::node::RejectReason;
use crate::{domain, Timestamp, MAX_FRAME_BYTES};

fixed_bytes!(
    /// Content-derived identifier of a signed envelope.
    ObjectId,
    32
);

/// Who may read the payload: one user on one device in Mission 001.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Audience {
    /// Recipient user.
    #[n(0)]
    pub user: UserId,
    /// Recipient device holding the HPKE private key.
    #[n(1)]
    pub device: DeviceId,
}

/// Encryption metadata needed to open the payload.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Encryption {
    /// Suite identifier; see [`crate::crypto`].
    #[n(0)]
    pub suite: u16,
    /// HPKE encapsulated key.
    #[n(1)]
    pub encapsulated_key: EncryptionKey,
}

/// Creator-declared routing bounds. Nodes clamp these to local policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Routing {
    /// Maximum number of transfers, counting the final delivery.
    #[n(0)]
    pub max_hops: u8,
    /// Creator priority hint, 0 (lowest) to 255. Unused by Mission 001 policy.
    #[n(1)]
    pub priority: u8,
}

/// Everything the creator device signs.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct EnvelopeBody {
    /// Wire protocol version; see [`crate::PROTOCOL_VERSION`].
    #[n(0)]
    pub version: u8,
    /// Application object type, e.g. `"text"`.
    #[n(1)]
    pub object_type: String,
    /// Creator user, device, and the user's authorization of that device.
    #[n(2)]
    pub creator: DeviceAuthorization,
    /// Creation time, creator's best-effort wall clock.
    #[n(3)]
    pub created_at: Timestamp,
    /// Expiry; the object is expired once `now >= expires_at`.
    #[n(4)]
    pub expires_at: Timestamp,
    /// Intended reader.
    #[n(5)]
    pub audience: Audience,
    /// Ciphertext length in bytes.
    #[n(6)]
    pub payload_size: u32,
    /// SHA-256 of the ciphertext.
    #[n(7)]
    pub payload_hash: Hash,
    /// How to open the payload.
    #[n(8)]
    pub encryption: Encryption,
    /// Routing bounds.
    #[n(9)]
    pub routing: Routing,
}

/// A signed, immutable envelope.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Envelope {
    /// Signed content.
    #[n(0)]
    pub body: EnvelopeBody,
    /// Creator device signature over the domain-separated canonical body.
    #[n(1)]
    pub signature: Sig,
}

impl Envelope {
    /// Signs `body` with `device`. The body must name `device` as creator.
    pub fn sign(body: EnvelopeBody, device: &DeviceIdentity) -> Self {
        let signature = device.sign(&Self::signing_input(&body));
        Self { body, signature }
    }

    fn signing_input(body: &EnvelopeBody) -> Vec<u8> {
        let mut input = domain::ENVELOPE_SIGNATURE.to_vec();
        input.extend(minicbor::to_vec(body).expect("encoding into Vec cannot fail"));
        input
    }

    /// Verifies the creator device signature. Does not check device authorization.
    pub fn verify_signature(&self) -> Result<(), IdentityError> {
        verify(
            &self.body.creator.body.device.0,
            &Self::signing_input(&self.body),
            &self.signature,
        )
    }

    /// Canonical CBOR bytes of the whole signed envelope.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        minicbor::to_vec(self).expect("encoding into Vec cannot fail")
    }

    /// Content-derived id: SHA-256 over the domain-separated canonical envelope.
    pub fn object_id(&self) -> ObjectId {
        ObjectId(sha256(&[domain::OBJECT_ID, &self.canonical_bytes()]).0)
    }

    /// The creator's user id.
    pub fn creator_user(&self) -> UserId {
        self.body.creator.body.user
    }

    /// The creator's device id.
    pub fn creator_device(&self) -> DeviceId {
        self.body.creator.body.device
    }
}

/// What a receiver tells a sender about an object transfer.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum AckOutcome {
    /// The receiver is the audience and decrypted the object.
    #[n(0)]
    Delivered,
    /// The receiver stored the opaque object for later forwarding.
    #[n(1)]
    CustodyAccepted,
    /// The receiver already had or delivered this object.
    #[n(2)]
    Duplicate,
    /// The receiver refused the object.
    #[n(3)]
    Rejected(#[n(0)] RejectReason),
}

/// Wire frames exchanged between two nodes in contact.
// `Object` dwarfs `Ack`, but frames are built once and moved straight to
// the codec; boxing the envelope would only add an allocation per packet.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Frame {
    /// An object transfer: envelope, ciphertext, and transport-local hop count.
    #[n(0)]
    #[cbor(map)]
    Object {
        /// The signed envelope.
        #[n(0)]
        envelope: Envelope,
        /// The HPKE ciphertext committed to by `envelope.body.payload_hash`.
        #[cbor(n(1), with = "minicbor::bytes")]
        ciphertext: Vec<u8>,
        /// Transfers so far including this one; 1 when sent by the creator.
        #[n(2)]
        hop_count: u8,
    },
    /// Receipt for an [`Frame::Object`].
    #[n(1)]
    #[cbor(map)]
    Ack {
        /// Which object.
        #[n(0)]
        object_id: ObjectId,
        /// What happened.
        #[n(1)]
        outcome: AckOutcome,
    },
}

/// Errors from frame decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// The frame exceeds [`MAX_FRAME_BYTES`].
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    /// The bytes are not a valid frame.
    #[error("malformed frame: {0}")]
    Malformed(String),
}

impl Frame {
    /// Canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        minicbor::to_vec(self).expect("encoding into Vec cannot fail")
    }

    /// Bounded decode: rejects oversized input before parsing.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge(bytes.len()));
        }
        minicbor::decode(bytes).map_err(|e| FrameError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305;
    use crate::identity::UserIdentity;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fixture() -> (DeviceIdentity, Envelope) {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let user = UserIdentity::generate(&mut rng);
        let creator = DeviceIdentity::generate(&user, 1_000, &mut rng);
        let recipient = DeviceIdentity::generate(&user, 1_000, &mut rng);
        let body = EnvelopeBody {
            version: 1,
            object_type: "text".into(),
            creator: creator.record().authorization,
            created_at: 1_700_000_000_000,
            expires_at: 1_700_000_060_000,
            audience: Audience {
                user: recipient.user(),
                device: recipient.id(),
            },
            payload_size: 21,
            payload_hash: Hash([0x11; 32]),
            encryption: Encryption {
                suite: SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
                encapsulated_key: EncryptionKey([0x22; 32]),
            },
            routing: Routing {
                max_hops: 2,
                priority: 0,
            },
        };
        let envelope = Envelope::sign(body, &creator);
        (creator, envelope)
    }

    #[test]
    fn canonical_encoding_is_pinned() {
        let (_, envelope) = fixture();
        let bytes = envelope.canonical_bytes();
        // Outer map of two entries; body is a map of ten entries with keys 0..=9.
        assert_eq!(bytes[0], 0xa2);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0xaa);
        // Pinned digest of the full canonical encoding; any codec change must
        // be a deliberate protocol version bump.
        let digest = sha256(&[&bytes]);
        assert_eq!(
            hex::encode(digest.0),
            "d50f48e2620504f12155eeacbc6eacd3d82adf3b87ec5368204a33856dc87fc2"
        );
        // Structural check of the deterministic profile: definite-length maps,
        // integer keys in ascending order, fixed fields as byte strings, and
        // shortest-form integers (payload_size 21 must encode as a u8 head).
        use minicbor::data::Type;
        let mut d = minicbor::Decoder::new(&bytes);
        assert_eq!(d.map().expect("outer map"), Some(2));
        assert_eq!(d.u8().expect("key"), 0);
        assert_eq!(d.map().expect("body map"), Some(10));
        let expected = [
            Type::U8,     // version
            Type::String, // object_type
            Type::Map,    // creator authorization
            Type::U64,    // created_at
            Type::U64,    // expires_at
            Type::Map,    // audience
            Type::U8,     // payload_size = 21
            Type::Bytes,  // payload_hash
            Type::Map,    // encryption
            Type::Map,    // routing
        ];
        for (key, ty) in expected.iter().enumerate() {
            assert_eq!(d.u8().expect("key") as usize, key);
            assert_eq!(&d.datatype().expect("type"), ty, "field {key}");
            d.skip().expect("skip");
        }
        assert_eq!(d.u8().expect("key"), 1);
        assert_eq!(d.datatype().expect("type"), Type::Bytes);
        assert_eq!(d.bytes().expect("signature").len(), 64);
        assert_eq!(d.position(), bytes.len(), "trailing bytes");
        let decoded: Envelope = minicbor::decode(&bytes).expect("decode");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.canonical_bytes(), bytes);
    }

    #[test]
    fn signature_verifies_and_any_body_change_breaks_it() {
        let (_, envelope) = fixture();
        assert_eq!(envelope.verify_signature(), Ok(()));
        let mut tampered = envelope.clone();
        tampered.body.payload_hash = Hash([0x12; 32]);
        assert_eq!(
            tampered.verify_signature(),
            Err(IdentityError::BadSignature)
        );
        let mut tampered = envelope.clone();
        tampered.body.audience.user = UserId([0; 32]);
        assert_eq!(
            tampered.verify_signature(),
            Err(IdentityError::BadSignature)
        );
        let mut tampered = envelope;
        tampered.signature.0[0] ^= 1;
        assert_eq!(
            tampered.verify_signature(),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn object_id_is_stable_and_changes_with_signature() {
        let (creator, envelope) = fixture();
        assert_eq!(envelope.object_id(), envelope.clone().object_id());
        let mut other_body = envelope.body.clone();
        other_body.payload_hash = Hash([0x13; 32]);
        let other = Envelope::sign(other_body, &creator);
        assert_ne!(other.object_id(), envelope.object_id());
    }

    #[test]
    fn frames_round_trip_and_bound_size() {
        let (_, envelope) = fixture();
        let frame = Frame::Object {
            envelope: envelope.clone(),
            ciphertext: vec![7; 21],
            hop_count: 1,
        };
        let bytes = frame.encode();
        assert_eq!(Frame::decode(&bytes), Ok(frame));
        let ack = Frame::Ack {
            object_id: envelope.object_id(),
            outcome: AckOutcome::Rejected(RejectReason::Expired),
        };
        assert_eq!(Frame::decode(&ack.encode()), Ok(ack));
        assert_eq!(
            Frame::decode(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(FrameError::TooLarge(MAX_FRAME_BYTES + 1))
        );
        assert!(matches!(
            Frame::decode(b"\xff"),
            Err(FrameError::Malformed(_))
        ));
    }
}
