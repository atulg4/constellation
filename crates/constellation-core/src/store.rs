//! Bounded in-memory custody store.
//!
//! Holds only signed envelopes and ciphertext. Enforces object size, object
//! count, per-peer count, and total byte quotas; expires by TTL. Mission 001
//! policy is reject-on-full: no priority eviction yet. Persistence across
//! process restart is deferred (see the ADR's non-goals).

use std::collections::{BTreeMap, BTreeSet};

use crate::envelope::{Envelope, ObjectId};
use crate::identity::DeviceId;
use crate::{Timestamp, MAX_CIPHERTEXT_BYTES};

/// Quotas for one node's store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorePolicy {
    /// Largest ciphertext accepted.
    pub max_object_bytes: usize,
    /// Total ciphertext bytes held.
    pub max_total_bytes: usize,
    /// Objects held, including the node's own pending submissions.
    pub max_objects: usize,
    /// Objects held from any single handing-over peer.
    pub max_objects_per_peer: usize,
}

impl Default for StorePolicy {
    fn default() -> Self {
        Self {
            max_object_bytes: MAX_CIPHERTEXT_BYTES,
            max_total_bytes: 8 * 1024 * 1024,
            max_objects: 256,
            max_objects_per_peer: 32,
        }
    }
}

/// Why an insert was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Ciphertext exceeds `max_object_bytes`.
    #[error("object too large")]
    TooLarge,
    /// A count or byte quota would be exceeded.
    #[error("store quota exceeded")]
    QuotaExceeded,
}

/// An object under custody, with its transport-local state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    /// Derived id.
    pub object_id: ObjectId,
    /// Signed envelope.
    pub envelope: Envelope,
    /// Opaque ciphertext.
    pub ciphertext: Vec<u8>,
    /// Transfers so far; 0 for the creator's own copy.
    pub hop_count: u8,
    /// Who handed it over, if not created locally.
    pub from: Option<DeviceId>,
    /// When it entered this store.
    pub received_at: Timestamp,
}

/// In-memory store with quotas and duplicate memory.
#[derive(Debug)]
pub struct MemoryStore {
    policy: StorePolicy,
    objects: BTreeMap<ObjectId, StoredObject>,
    seen: BTreeSet<ObjectId>,
    total_bytes: usize,
}

impl MemoryStore {
    /// An empty store under `policy`.
    pub fn new(policy: StorePolicy) -> Self {
        Self {
            policy,
            objects: BTreeMap::new(),
            seen: BTreeSet::new(),
            total_bytes: 0,
        }
    }

    /// Whether this id was ever accepted, delivered, or created here.
    pub fn seen(&self, id: &ObjectId) -> bool {
        self.seen.contains(id)
    }

    /// Remembers `id` for duplicate suppression without storing bytes.
    pub fn mark_seen(&mut self, id: ObjectId) {
        self.seen.insert(id);
    }

    /// Inserts under quota. Marks the id seen on success.
    pub fn insert(&mut self, object: StoredObject) -> Result<(), StoreError> {
        let size = object.ciphertext.len();
        if size > self.policy.max_object_bytes {
            return Err(StoreError::TooLarge);
        }
        if self.objects.len() >= self.policy.max_objects
            || self.total_bytes + size > self.policy.max_total_bytes
        {
            return Err(StoreError::QuotaExceeded);
        }
        if let Some(peer) = object.from {
            let from_peer = self
                .objects
                .values()
                .filter(|o| o.from == Some(peer))
                .count();
            if from_peer >= self.policy.max_objects_per_peer {
                return Err(StoreError::QuotaExceeded);
            }
        }
        self.total_bytes += size;
        self.seen.insert(object.object_id);
        self.objects.insert(object.object_id, object);
        Ok(())
    }

    /// Removes and returns an object; it stays remembered as seen.
    pub fn remove(&mut self, id: &ObjectId) -> Option<StoredObject> {
        let removed = self.objects.remove(id)?;
        self.total_bytes -= removed.ciphertext.len();
        Some(removed)
    }

    /// Looks up an object.
    pub fn get(&self, id: &ObjectId) -> Option<&StoredObject> {
        self.objects.get(id)
    }

    /// All held objects in id order.
    pub fn iter(&self) -> impl Iterator<Item = &StoredObject> {
        self.objects.values()
    }

    /// Number of held objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Drops every object with `expires_at <= now`; returns their ids.
    pub fn expire(&mut self, now: Timestamp) -> Vec<ObjectId> {
        let expired: Vec<ObjectId> = self
            .objects
            .values()
            .filter(|o| now >= o.envelope.body.expires_at)
            .map(|o| o.object_id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Hash, SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305};
    use crate::envelope::{Audience, Encryption, EnvelopeBody, Routing};
    use crate::identity::{DeviceIdentity, EncryptionKey, UserIdentity};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn object(tag: u8, size: usize, from: Option<DeviceId>, expires_at: Timestamp) -> StoredObject {
        let mut rng = ChaCha20Rng::from_seed([tag; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 0, &mut rng);
        let body = EnvelopeBody {
            version: 1,
            object_type: "text".into(),
            creator: device.record().authorization,
            created_at: 0,
            expires_at,
            audience: Audience {
                user: device.user(),
                device: device.id(),
            },
            payload_size: size as u32,
            payload_hash: Hash([tag; 32]),
            encryption: Encryption {
                suite: SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
                encapsulated_key: EncryptionKey([0; 32]),
            },
            routing: Routing {
                max_hops: 2,
                priority: 0,
            },
        };
        let envelope = Envelope::sign(body, &device);
        StoredObject {
            object_id: envelope.object_id(),
            envelope,
            ciphertext: vec![tag; size],
            hop_count: 1,
            from,
            received_at: 0,
        }
    }

    #[test]
    fn quotas_are_enforced_and_removal_frees_space() {
        let mut store = MemoryStore::new(StorePolicy {
            max_object_bytes: 100,
            max_total_bytes: 150,
            max_objects: 10,
            max_objects_per_peer: 1,
        });
        let peer = DeviceId([9; 32]);
        assert_eq!(
            store.insert(object(1, 101, None, 10)),
            Err(StoreError::TooLarge)
        );
        assert_eq!(store.insert(object(1, 100, Some(peer), 10)), Ok(()));
        assert_eq!(
            store.insert(object(2, 10, Some(peer), 10)),
            Err(StoreError::QuotaExceeded)
        );
        assert_eq!(
            store.insert(object(3, 60, None, 10)),
            Err(StoreError::QuotaExceeded)
        );
        assert_eq!(store.insert(object(3, 50, None, 10)), Ok(()));
        let first = object(1, 100, Some(peer), 10).object_id;
        assert!(store.remove(&first).is_some());
        assert!(store.seen(&first));
        assert_eq!(store.insert(object(2, 10, Some(peer), 10)), Ok(()));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn expiry_uses_now_at_or_after_expires_at() {
        let mut store = MemoryStore::new(StorePolicy::default());
        store.insert(object(1, 5, None, 100)).expect("insert");
        store.insert(object(2, 5, None, 200)).expect("insert");
        assert!(store.expire(99).is_empty());
        assert_eq!(store.expire(100).len(), 1);
        assert_eq!(store.len(), 1);
        assert_eq!(store.expire(500).len(), 1);
        assert!(store.is_empty());
    }
}
