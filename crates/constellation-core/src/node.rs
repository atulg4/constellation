//! A Constellation node: creates objects, validates incoming ones in a fixed
//! order, accepts bounded custody, delivers to itself, and emits
//! privacy-safe lifecycle events.
//!
//! Validation order for an incoming object (first failure wins):
//! version → payload bounds → suite → creator trust → device authorization →
//! signature → TTL and clock skew → hop limit → audience/custody policy →
//! ciphertext hash → duplicate → decrypt or store.

use std::collections::{BTreeMap, BTreeSet};

use minicbor::{Decode, Encode};
use rand_core::CryptoRng;

use crate::crypto::{self, sha256, CryptoError, SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305};
use crate::envelope::{
    AckOutcome, Audience, Encryption, Envelope, EnvelopeBody, Frame, ObjectId, Routing,
};
use crate::identity::{ContactBook, DeviceId, DeviceIdentity, DeviceRecord, EncryptionKey, UserId};
pub use crate::store::StorePolicy;
use crate::store::{MemoryStore, StoreError, StoredObject};
use crate::{domain, Timestamp, MAX_CIPHERTEXT_BYTES, MAX_PLAINTEXT_BYTES, PROTOCOL_VERSION};

/// Local policy for one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Whether this node stores objects for others.
    pub accept_custody: bool,
    /// Hard cap on hops this node honours, whatever the creator declared.
    pub max_hops: u8,
    /// How far in the future a creator's `created_at` may be.
    pub max_clock_skew_ms: u64,
    /// Store quotas.
    pub store: StorePolicy,
    /// Decrypted objects held in the inbox before new deliveries are refused.
    /// Applications drain it with [`Node::take_inbox`].
    pub max_inbox: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            accept_custody: false,
            max_hops: 2,
            max_clock_skew_ms: 5 * 60_000,
            store: StorePolicy::default(),
            max_inbox: 256,
        }
    }
}

/// What a node knows about a peer it is in contact with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer device.
    pub device: DeviceId,
    /// Peer's user.
    pub user: UserId,
    /// Whether the peer advertises carrying for others.
    pub accepts_custody: bool,
}

/// Why an object was refused. Carried on the wire in acks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum RejectReason {
    /// Structurally invalid.
    #[n(0)]
    Malformed,
    /// Envelope version not supported.
    #[n(1)]
    UnsupportedVersion,
    /// Ciphertext exceeds bounds.
    #[n(2)]
    PayloadTooLarge,
    /// Encryption suite not supported.
    #[n(3)]
    UnsupportedSuite,
    /// Creator's user key is not in the contact book.
    #[n(4)]
    UntrustedCreator,
    /// The user's authorization of the creator device does not verify.
    #[n(5)]
    BadDeviceAuthorization,
    /// Envelope signature does not verify.
    #[n(6)]
    BadSignature,
    /// `now >= expires_at`.
    #[n(7)]
    Expired,
    /// `created_at` is too far in the future.
    #[n(8)]
    ClockSkew,
    /// Hop count over the effective limit, or no room for a further hop.
    #[n(9)]
    HopLimitExceeded,
    /// Addressed to this device but not to this user.
    #[n(10)]
    UnauthorizedRecipient,
    /// This node does not carry for others.
    #[n(11)]
    CustodyRefused,
    /// Ciphertext does not match the signed commitment.
    #[n(12)]
    PayloadHashMismatch,
    /// Store quota exhausted.
    #[n(13)]
    QuotaExceeded,
    /// Authenticated decryption failed.
    #[n(14)]
    DecryptionFailed,
    /// Custody offered by someone other than the creator: one custody hop only.
    #[n(15)]
    CustodyNotFromCreator,
}

/// Lifecycle states reported in events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectState {
    /// Created locally and waiting for a path.
    Submitted,
    /// Stored for someone else.
    CustodyAccepted,
    /// A peer accepted custody of our copy.
    Forwarded,
    /// Reached the audience (on the audience: decrypted; on the sender: acked).
    Delivered,
    /// Refused, with reason.
    Rejected(RejectReason),
    /// Dropped by TTL.
    Expired,
    /// Already known; ignored.
    Duplicate,
}

/// Node-local pseudonym for a peer. Stable per node, meaningless elsewhere.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerTag([u8; 4]);

impl core::fmt::Debug for PeerTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "peer:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// One lifecycle transition. Never contains plaintext, keys, or raw peer ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// When it happened.
    pub at: Timestamp,
    /// Which object.
    pub object_id: ObjectId,
    /// New state.
    pub state: ObjectState,
    /// Pseudonymous counterpart, if any.
    pub peer: Option<PeerTag>,
}

/// A decrypted object in the inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Object id.
    pub object_id: ObjectId,
    /// Verified creator user.
    pub creator_user: UserId,
    /// Verified creator device.
    pub creator_device: DeviceId,
    /// Application object type.
    pub object_type: String,
    /// Decrypted payload.
    pub plaintext: Vec<u8>,
    /// Local receipt time.
    pub received_at: Timestamp,
}

/// Errors creating an object.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubmitError {
    /// Plaintext exceeds [`MAX_PLAINTEXT_BYTES`].
    #[error("payload exceeds {MAX_PLAINTEXT_BYTES} bytes")]
    PayloadTooLarge,
    /// TTL must be positive.
    #[error("ttl must be positive")]
    ZeroTtl,
    /// The recipient record's authorization does not verify or does not match
    /// its user, device and encryption key.
    #[error("recipient record is not authorized by its user")]
    InvalidRecipient,
    /// Encryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Local store refused the new object.
    #[error(transparent)]
    Store(#[from] StoreError),
}

enum Accepted {
    Delivered,
    Custody,
}

/// A device's runtime state.
#[derive(Debug)]
pub struct Node {
    device: DeviceIdentity,
    contacts: ContactBook,
    policy: Policy,
    store: MemoryStore,
    inbox: Vec<Delivered>,
    events: Vec<Event>,
    salt: [u8; 32],
    /// Which peers each held object was offered to, so only those peers'
    /// acknowledgements can release it.
    offered: BTreeMap<ObjectId, BTreeSet<DeviceId>>,
}

impl Node {
    /// Creates a node for `device` trusting `contacts` under `policy`.
    pub fn new(device: DeviceIdentity, contacts: ContactBook, policy: Policy) -> Self {
        let salt = device.local_salt();
        let store = MemoryStore::new(policy.store.clone());
        Self {
            device,
            contacts,
            policy,
            store,
            inbox: Vec::new(),
            events: Vec::new(),
            salt,
            offered: BTreeMap::new(),
        }
    }

    /// This device's id.
    pub fn id(&self) -> DeviceId {
        self.device.id()
    }

    /// This device's public record, for senders.
    pub fn record(&self) -> DeviceRecord {
        self.device.record()
    }

    /// How this node presents itself to peers.
    pub fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            device: self.device.id(),
            user: self.device.user(),
            accepts_custody: self.policy.accept_custody,
        }
    }

    /// Decrypted objects addressed to this device, in arrival order.
    pub fn inbox(&self) -> &[Delivered] {
        &self.inbox
    }

    /// Removes and returns every delivered object, freeing inbox capacity.
    pub fn take_inbox(&mut self) -> Vec<Delivered> {
        std::mem::take(&mut self.inbox)
    }

    /// Lifecycle events, in order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Everything currently held: own pending objects and custody for others.
    pub fn custody(&self) -> Vec<&StoredObject> {
        self.store.iter().collect()
    }

    /// Builds a signed envelope and ciphertext without storing it.
    pub fn build_object(
        &self,
        audience: Audience,
        recipient_key: &EncryptionKey,
        plaintext: &[u8],
        ttl_ms: u64,
        now: Timestamp,
        rng: &mut impl CryptoRng,
    ) -> Result<(Envelope, Vec<u8>), SubmitError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(SubmitError::PayloadTooLarge);
        }
        if ttl_ms == 0 {
            return Err(SubmitError::ZeroTtl);
        }
        let aad = crypto::payload_aad(&self.device.id(), &audience);
        let (encapsulated_key, ciphertext) = crypto::seal(recipient_key, &aad, plaintext, rng)?;
        let body = EnvelopeBody {
            version: PROTOCOL_VERSION,
            object_type: "text".into(),
            creator: self.device.record().authorization,
            created_at: now,
            expires_at: now.saturating_add(ttl_ms),
            audience,
            payload_size: ciphertext.len() as u32,
            payload_hash: sha256(&[&ciphertext]),
            encryption: Encryption {
                suite: SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
                encapsulated_key,
            },
            routing: Routing {
                max_hops: self.policy.max_hops,
                priority: 0,
            },
        };
        Ok((Envelope::sign(body, &self.device), ciphertext))
    }

    /// Creates an object for `recipient` and queues it locally.
    pub fn submit(
        &mut self,
        recipient: &DeviceRecord,
        plaintext: &[u8],
        ttl_ms: u64,
        now: Timestamp,
        rng: &mut impl CryptoRng,
    ) -> Result<ObjectId, SubmitError> {
        let auth = &recipient.authorization;
        if auth.verify().is_err()
            || auth.body.user != recipient.user
            || auth.body.device != recipient.device
            || auth.body.encryption_key != recipient.encryption_key
        {
            return Err(SubmitError::InvalidRecipient);
        }
        self.expire(now);
        let audience = Audience {
            user: recipient.user,
            device: recipient.device,
        };
        let (envelope, ciphertext) = self.build_object(
            audience,
            &recipient.encryption_key,
            plaintext,
            ttl_ms,
            now,
            rng,
        )?;
        let object_id = envelope.object_id();
        self.store.insert(StoredObject {
            object_id,
            envelope,
            ciphertext,
            hop_count: 0,
            from: None,
            received_at: now,
        })?;
        self.emit(now, object_id, ObjectState::Submitted, None);
        Ok(object_id)
    }

    /// Drops expired objects, emitting an event for each.
    pub fn expire(&mut self, now: Timestamp) {
        for id in self.store.expire(now) {
            self.offered.remove(&id);
            self.emit(now, id, ObjectState::Expired, None);
        }
    }

    /// A peer came into contact: decide what to hand it.
    ///
    /// Objects addressed to the peer are always offered. Custody is offered
    /// only for objects this node created (one custody hop, ADR-0006), only
    /// when another hop remains within the limit, and only to a peer whose
    /// user is in the contact book: advertising `accepts_custody` is a
    /// capability, never an authorization.
    pub fn on_connect(&mut self, peer: &PeerInfo, now: Timestamp) -> Vec<Frame> {
        self.expire(now);
        let trusted_carrier = peer.accepts_custody && self.contacts.is_trusted(&peer.user);
        let mut frames = Vec::new();
        let mut offered = Vec::new();
        for object in self.store.iter() {
            let body = &object.envelope.body;
            let next_hop = object.hop_count + 1;
            let limit = self.effective_max_hops(body);
            let for_peer = body.audience.device == peer.device;
            let custody_ok = object.hop_count == 0 && trusted_carrier && next_hop < limit;
            if (for_peer && next_hop <= limit) || custody_ok {
                offered.push(object.object_id);
                frames.push(Frame::Object {
                    envelope: object.envelope.clone(),
                    ciphertext: object.ciphertext.clone(),
                    hop_count: next_hop,
                });
            }
        }
        for id in offered {
            self.offered.entry(id).or_default().insert(peer.device);
        }
        frames
    }

    /// Handles one frame from `from`; returns frames to send back.
    pub fn handle_frame(&mut self, from: &PeerInfo, frame: Frame, now: Timestamp) -> Vec<Frame> {
        match frame {
            Frame::Object {
                envelope,
                ciphertext,
                hop_count,
            } => {
                let object_id = envelope.object_id();
                let tag = self.tag(&from.device);
                let outcome = match self.accept(from, envelope, ciphertext, hop_count, now) {
                    Ok(Accepted::Delivered) => {
                        self.emit(now, object_id, ObjectState::Delivered, Some(tag));
                        AckOutcome::Delivered
                    }
                    Ok(Accepted::Custody) => {
                        self.emit(now, object_id, ObjectState::CustodyAccepted, Some(tag));
                        AckOutcome::CustodyAccepted
                    }
                    Err(None) => {
                        self.emit(now, object_id, ObjectState::Duplicate, Some(tag));
                        AckOutcome::Duplicate
                    }
                    Err(Some(reason)) => {
                        self.emit(now, object_id, ObjectState::Rejected(reason), Some(tag));
                        AckOutcome::Rejected(reason)
                    }
                };
                vec![Frame::Ack { object_id, outcome }]
            }
            Frame::Ack { object_id, outcome } => {
                self.handle_ack(from, object_id, outcome, now);
                Vec::new()
            }
        }
    }

    fn handle_ack(
        &mut self,
        from: &PeerInfo,
        object_id: ObjectId,
        outcome: AckOutcome,
        now: Timestamp,
    ) {
        // Only a peer this object was actually offered to may release it.
        let Some(object) = self.store.get(&object_id) else {
            return;
        };
        if !self
            .offered
            .get(&object_id)
            .is_some_and(|peers| peers.contains(&from.device))
        {
            return;
        }
        let from_audience = object.envelope.body.audience.device == from.device;
        let created_here = object.hop_count == 0;
        let tag = Some(self.tag(&from.device));
        match outcome {
            // Delivery can only be claimed by the audience device itself.
            AckOutcome::Delivered | AckOutcome::Duplicate if from_audience => {
                self.release(&object_id);
                self.emit(now, object_id, ObjectState::Delivered, tag);
            }
            // Custody hand-off only exists for objects this node created.
            AckOutcome::CustodyAccepted if created_here && !from_audience => {
                self.release(&object_id);
                self.emit(now, object_id, ObjectState::Forwarded, tag);
            }
            AckOutcome::Delivered | AckOutcome::Duplicate | AckOutcome::CustodyAccepted => {}
            AckOutcome::Rejected(reason) => {
                self.emit(now, object_id, ObjectState::Rejected(reason), tag);
            }
        }
    }

    fn release(&mut self, object_id: &ObjectId) {
        self.store.remove(object_id);
        self.offered.remove(object_id);
    }

    /// The fixed-order validation pipeline. `Err(None)` means duplicate.
    fn accept(
        &mut self,
        from: &PeerInfo,
        envelope: Envelope,
        ciphertext: Vec<u8>,
        hop_count: u8,
        now: Timestamp,
    ) -> Result<Accepted, Option<RejectReason>> {
        // An exact envelope we already hold or delivered is dropped before any
        // signature, hash or decryption work: the id commits to the signed
        // envelope, so a replay cannot buy CPU or battery.
        let object_id = envelope.object_id();
        if self.store.seen(&object_id) {
            return Err(None);
        }
        let body = &envelope.body;
        if body.version != PROTOCOL_VERSION {
            return Err(Some(RejectReason::UnsupportedVersion));
        }
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Some(RejectReason::PayloadTooLarge));
        }
        if body.encryption.suite != SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 {
            return Err(Some(RejectReason::UnsupportedSuite));
        }
        if !self.contacts.is_trusted(&body.creator.body.user) {
            return Err(Some(RejectReason::UntrustedCreator));
        }
        if body.creator.verify().is_err() {
            return Err(Some(RejectReason::BadDeviceAuthorization));
        }
        if envelope.verify_signature().is_err() {
            return Err(Some(RejectReason::BadSignature));
        }
        if body.expires_at <= body.created_at {
            return Err(Some(RejectReason::Malformed));
        }
        if now >= body.expires_at {
            return Err(Some(RejectReason::Expired));
        }
        if body.created_at > now.saturating_add(self.policy.max_clock_skew_ms) {
            return Err(Some(RejectReason::ClockSkew));
        }
        let limit = self.effective_max_hops(body);
        if hop_count == 0 || hop_count > limit {
            return Err(Some(RejectReason::HopLimitExceeded));
        }
        let addressed_to_me = body.audience.device == self.device.id();
        if addressed_to_me {
            if body.audience.user != self.device.user() {
                return Err(Some(RejectReason::UnauthorizedRecipient));
            }
        } else {
            if !self.policy.accept_custody {
                return Err(Some(RejectReason::CustodyRefused));
            }
            if hop_count >= limit {
                return Err(Some(RejectReason::HopLimitExceeded));
            }
            // One custody hop: only the signed creator may hand custody over.
            if from.device != body.creator.body.device || hop_count != 1 {
                return Err(Some(RejectReason::CustodyNotFromCreator));
            }
        }
        if ciphertext.len() != body.payload_size as usize
            || sha256(&[&ciphertext]) != body.payload_hash
        {
            return Err(Some(RejectReason::PayloadHashMismatch));
        }
        if addressed_to_me {
            if self.inbox.len() >= self.policy.max_inbox {
                return Err(Some(RejectReason::QuotaExceeded));
            }
            let plaintext = crypto::open_payload(&self.device, &envelope, &ciphertext)
                .map_err(|_| Some(RejectReason::DecryptionFailed))?;
            self.store.mark_seen(object_id);
            self.inbox.push(Delivered {
                object_id,
                creator_user: envelope.creator_user(),
                creator_device: envelope.creator_device(),
                object_type: envelope.body.object_type.clone(),
                plaintext,
                received_at: now,
            });
            return Ok(Accepted::Delivered);
        }
        self.store
            .insert(StoredObject {
                object_id,
                envelope,
                ciphertext,
                hop_count,
                from: Some(from.device),
                received_at: now,
            })
            .map_err(|e| {
                Some(match e {
                    StoreError::TooLarge => RejectReason::PayloadTooLarge,
                    StoreError::QuotaExceeded => RejectReason::QuotaExceeded,
                })
            })?;
        Ok(Accepted::Custody)
    }

    fn effective_max_hops(&self, body: &EnvelopeBody) -> u8 {
        body.routing.max_hops.min(self.policy.max_hops)
    }

    fn tag(&self, peer: &DeviceId) -> PeerTag {
        let digest = sha256(&[domain::PEER_TAG, &self.salt, &peer.0]);
        PeerTag([digest.0[0], digest.0[1], digest.0[2], digest.0[3]])
    }

    fn emit(
        &mut self,
        at: Timestamp,
        object_id: ObjectId,
        state: ObjectState,
        peer: Option<PeerTag>,
    ) {
        self.events.push(Event {
            at,
            object_id,
            state,
            peer,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::UserIdentity;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn node(seed: u8, accept_custody: bool) -> Node {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 0, &mut rng);
        let mut book = ContactBook::new();
        book.trust_user(user.id());
        Node::new(
            device,
            book,
            Policy {
                accept_custody,
                ..Policy::default()
            },
        )
    }

    #[test]
    fn submit_rejects_zero_ttl_and_oversized_payload() {
        let mut a = node(1, false);
        let c = node(2, false);
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let record = c.device.record();
        assert_eq!(
            a.submit(&record, b"x", 0, 10, &mut rng),
            Err(SubmitError::ZeroTtl)
        );
        let big = vec![0; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            a.submit(&record, &big, 1, 10, &mut rng),
            Err(SubmitError::PayloadTooLarge)
        );
        assert!(a.submit(&record, b"x", 1, 10, &mut rng).is_ok());
        assert_eq!(a.events().len(), 1);
        assert_eq!(a.events()[0].state, ObjectState::Submitted);
    }

    #[test]
    fn clock_skew_beyond_policy_is_rejected() {
        let a = node(1, false);
        let mut c = node(2, false);
        c.contacts.trust_user(a.device.user());
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let record = c.device.record();
        let far_future = 1_000_000 + c.policy.max_clock_skew_ms + 1;
        let (envelope, ciphertext) = a
            .build_object(
                Audience {
                    user: record.user,
                    device: record.device,
                },
                &record.encryption_key,
                b"hi",
                60_000,
                far_future,
                &mut rng,
            )
            .expect("build");
        let acks = c.handle_frame(
            &a.peer_info(),
            Frame::Object {
                envelope,
                ciphertext,
                hop_count: 1,
            },
            1_000_000,
        );
        assert!(matches!(
            acks[0],
            Frame::Ack {
                outcome: AckOutcome::Rejected(RejectReason::ClockSkew),
                ..
            }
        ));
    }

    #[test]
    fn peer_tags_are_stable_per_node_and_differ_across_nodes() {
        let a = node(1, false);
        let b = node(2, false);
        let peer = DeviceId([5; 32]);
        assert_eq!(a.tag(&peer), a.tag(&peer));
        assert_ne!(a.tag(&peer), b.tag(&peer));
        assert_ne!(a.tag(&peer), a.tag(&DeviceId([6; 32])));
    }
}
