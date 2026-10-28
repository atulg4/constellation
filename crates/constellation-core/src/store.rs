//! Bounded custody stores.
//!
//! A store holds only signed envelopes and ciphertext. It enforces object
//! size, object count, per-peer count, and total byte quotas; expires by TTL;
//! and remembers every id it has seen for duplicate suppression. Mission 001
//! policy is reject-on-full: no priority eviction yet.
//!
//! [`MemoryStore`] lives for the process. [`FileStore`] keeps the same
//! behaviour and additionally persists every accepted object under a
//! directory so a carrier survives a restart between accepting custody and
//! meeting the recipient. Nothing a store writes is ever plaintext.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use minicbor::{Decode, Encode};

use crate::crypto::sha256;
use crate::envelope::{Envelope, ObjectId};
use crate::{Timestamp, MAX_CIPHERTEXT_BYTES, MAX_FRAME_BYTES};

/// Most seen ids a [`FileStore`] reads back at open. Ids beyond this bound
/// are dropped at load, which can only cause a duplicate to be re-examined
/// by the full validation pipeline, never a plaintext or custody error.
pub const MAX_SEEN_IDS: usize = 1 << 16;

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
    /// The backing storage could not be written. Carries no path or OS
    /// detail so it is safe to surface in events and acks.
    #[error("store unavailable")]
    Io,
}

fixed_bytes!(
    /// Node-local pseudonym of the peer that handed an object over: a keyed
    /// hash of its device id under a secret only this node holds. Used for
    /// per-peer quotas; a store never holds the raw peer id.
    PeerKey,
    32
);

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
    pub from: Option<PeerKey>,
    /// When it entered this store.
    pub received_at: Timestamp,
}

/// What a node needs from its custody store.
///
/// Every method is infallible except [`insert`](Self::insert): a backend
/// that cannot record a removal or a seen id keeps the in-memory truth and
/// at worst re-offers or re-examines an object after a restart, which the
/// validation pipeline already handles.
pub trait ObjectStore: core::fmt::Debug {
    /// Whether this id was ever accepted, delivered, or created here.
    fn seen(&self, id: &ObjectId) -> bool;
    /// Remembers `id` for duplicate suppression without storing bytes.
    fn mark_seen(&mut self, id: ObjectId);
    /// Inserts under quota. Marks the id seen on success.
    fn insert(&mut self, object: StoredObject) -> Result<(), StoreError>;
    /// Removes and returns an object; it stays remembered as seen.
    fn remove(&mut self, id: &ObjectId) -> Option<StoredObject>;
    /// Looks up an object.
    fn get(&self, id: &ObjectId) -> Option<&StoredObject>;
    /// All held objects in id order.
    fn iter(&self) -> Box<dyn Iterator<Item = &StoredObject> + '_>;
    /// Number of held objects.
    fn len(&self) -> usize;
    /// Whether nothing is held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Drops every object with `expires_at <= now`; returns their ids.
    fn expire(&mut self, now: Timestamp) -> Vec<ObjectId>;
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
}

impl ObjectStore for MemoryStore {
    fn seen(&self, id: &ObjectId) -> bool {
        self.seen.contains(id)
    }

    fn mark_seen(&mut self, id: ObjectId) {
        self.seen.insert(id);
    }

    fn insert(&mut self, object: StoredObject) -> Result<(), StoreError> {
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

    fn remove(&mut self, id: &ObjectId) -> Option<StoredObject> {
        let removed = self.objects.remove(id)?;
        self.total_bytes -= removed.ciphertext.len();
        Some(removed)
    }

    fn get(&self, id: &ObjectId) -> Option<&StoredObject> {
        self.objects.get(id)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = &StoredObject> + '_> {
        Box::new(self.objects.values())
    }

    fn len(&self) -> usize {
        self.objects.len()
    }

    fn expire(&mut self, now: Timestamp) -> Vec<ObjectId> {
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

/// On-disk form of one held object: exactly what [`StoredObject`] holds,
/// in canonical CBOR. Never contains plaintext or any key material.
#[derive(Encode, Decode)]
#[cbor(map)]
struct Record {
    #[n(0)]
    envelope: Envelope,
    #[cbor(n(1), with = "minicbor::bytes")]
    ciphertext: Vec<u8>,
    #[n(2)]
    hop_count: u8,
    #[n(3)]
    from: Option<PeerKey>,
    #[n(4)]
    received_at: Timestamp,
}

/// Largest on-disk record: an accepted frame plus the transport-local fields
/// a record adds (handing-over peer key, receipt time, CBOR heads).
pub const MAX_RECORD_BYTES: usize = MAX_FRAME_BYTES + 128;

const OBJECTS_DIR: &str = "objects";
const SEEN_FILE: &str = "seen.bin";
const OBJECT_EXT: &str = "cbor";
const TEMP_EXT: &str = "tmp";

/// A [`MemoryStore`] mirrored to a directory.
///
/// Layout under the root: `objects/<object id as hex>.cbor` holds one
/// [`Record`] per held object and `seen.bin` is the concatenation of every
/// seen 32-byte id. Each write goes to a `.tmp` sibling, is synced, and is
/// renamed into place, so a crash leaves either the old or the new file.
/// Objects are only inserted after the node's validation pipeline accepted
/// them, and every entry is re-checked at open: bounded size, well-formed
/// CBOR, id matching its file name, ciphertext matching the signed
/// commitment, and the current quotas. Entries that fail are skipped and
/// counted, never trusted and never a panic.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
    memory: MemoryStore,
    rejected_at_load: usize,
}

impl FileStore {
    /// Opens or creates the store at `root` and loads what it holds.
    pub fn open(root: impl AsRef<Path>, policy: StorePolicy) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(OBJECTS_DIR))?;
        let mut store = Self {
            root,
            memory: MemoryStore::new(policy),
            rejected_at_load: 0,
        };
        store.load_seen()?;
        store.load_objects()?;
        Ok(store)
    }

    /// The directory this store persists under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Entries skipped at open because they were corrupt, oversized,
    /// inconsistent with their envelope, or over quota.
    pub fn rejected_at_load(&self) -> usize {
        self.rejected_at_load
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join(OBJECTS_DIR)
    }

    fn object_path(&self, id: &ObjectId) -> PathBuf {
        self.objects_dir()
            .join(format!("{}.{OBJECT_EXT}", hex(id.as_bytes())))
    }

    fn load_seen(&mut self) -> io::Result<()> {
        let path = self.root.join(SEEN_FILE);
        remove_stale_temp(&path);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let limit = MAX_SEEN_IDS * ObjectId::LEN;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            self.rejected_at_load += 1;
            bytes.truncate(limit);
        }
        let mut chunks = bytes.chunks_exact(ObjectId::LEN);
        for chunk in &mut chunks {
            let mut id = [0u8; ObjectId::LEN];
            id.copy_from_slice(chunk);
            self.memory.mark_seen(ObjectId(id));
        }
        if !chunks.remainder().is_empty() {
            self.rejected_at_load += 1;
        }
        Ok(())
    }

    fn load_objects(&mut self) -> io::Result<()> {
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(self.objects_dir())? {
            let path = entry?.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some(OBJECT_EXT) => paths.push(path),
                Some(TEMP_EXT) => {
                    let _ = fs::remove_file(&path);
                }
                _ => {}
            }
        }
        paths.sort();
        for path in paths {
            let accepted =
                read_record(&path).is_some_and(|object| self.memory.insert(object).is_ok());
            if !accepted {
                self.rejected_at_load += 1;
            }
        }
        Ok(())
    }

    fn write_seen(&self) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(self.memory.seen.len() * ObjectId::LEN);
        for id in self.memory.seen.iter().take(MAX_SEEN_IDS) {
            bytes.extend_from_slice(id.as_bytes());
        }
        write_atomic(&self.root.join(SEEN_FILE), &bytes)
    }

    fn write_object(&self, object: &StoredObject) -> io::Result<()> {
        let record = Record {
            envelope: object.envelope.clone(),
            ciphertext: object.ciphertext.clone(),
            hop_count: object.hop_count,
            from: object.from,
            received_at: object.received_at,
        };
        let bytes = minicbor::to_vec(&record).expect("encoding into Vec cannot fail");
        write_atomic(&self.object_path(&object.object_id), &bytes)
    }
}

impl ObjectStore for FileStore {
    fn seen(&self, id: &ObjectId) -> bool {
        self.memory.seen(id)
    }

    fn mark_seen(&mut self, id: ObjectId) {
        if self.memory.seen(&id) {
            return;
        }
        self.memory.mark_seen(id);
        let _ = self.write_seen();
    }

    fn insert(&mut self, object: StoredObject) -> Result<(), StoreError> {
        let id = object.object_id;
        let was_seen = self.memory.seen(&id);
        self.memory.insert(object)?;
        let written = self
            .write_object(self.memory.get(&id).expect("just inserted"))
            .and_then(|()| self.write_seen());
        if written.is_err() {
            let _ = fs::remove_file(self.object_path(&id));
            self.memory.remove(&id);
            // A refused object must not later read as a duplicate.
            if !was_seen {
                self.memory.seen.remove(&id);
            }
            return Err(StoreError::Io);
        }
        Ok(())
    }

    fn remove(&mut self, id: &ObjectId) -> Option<StoredObject> {
        let removed = self.memory.remove(id)?;
        let _ = fs::remove_file(self.object_path(id));
        Some(removed)
    }

    fn get(&self, id: &ObjectId) -> Option<&StoredObject> {
        self.memory.get(id)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = &StoredObject> + '_> {
        self.memory.iter()
    }

    fn len(&self) -> usize {
        self.memory.len()
    }

    fn expire(&mut self, now: Timestamp) -> Vec<ObjectId> {
        let expired = self.memory.expire(now);
        for id in &expired {
            let _ = fs::remove_file(self.object_path(id));
        }
        expired
    }
}

/// Reads and re-validates one object file. `None` means skip it.
fn read_record(path: &Path) -> Option<StoredObject> {
    let len = fs::metadata(path).ok()?.len();
    if len > MAX_RECORD_BYTES as u64 {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let record: Record = minicbor::decode(&bytes).ok()?;
    let body = &record.envelope.body;
    if record.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || record.ciphertext.len() != body.payload_size as usize
        || sha256(&[&record.ciphertext]) != body.payload_hash
    {
        return None;
    }
    // Transport-local state must be one the node could have written: its own
    // submission is hop 0 with no handing-over peer; a received object is
    // hop 1..=max_hops with one.
    let hops_ok = match record.from {
        None => record.hop_count == 0,
        Some(_) => (1..=body.routing.max_hops).contains(&record.hop_count),
    };
    if !hops_ok {
        return None;
    }
    let object_id = record.envelope.object_id();
    let stem = path.file_stem().and_then(|s| s.to_str())?;
    if stem != hex(object_id.as_bytes()) {
        return None;
    }
    Some(StoredObject {
        object_id,
        envelope: record.envelope,
        ciphertext: record.ciphertext,
        hop_count: record.hop_count,
        from: record.from,
        received_at: record.received_at,
    })
}

/// Writes `bytes` to a `.tmp` sibling, syncs it, and renames it over `path`.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(TEMP_EXT);
    let result = (|| {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn remove_stale_temp(path: &Path) {
    let _ = fs::remove_file(path.with_extension(TEMP_EXT));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305;
    use crate::envelope::{Audience, Encryption, EnvelopeBody, Routing};
    use crate::identity::{DeviceIdentity, EncryptionKey, UserIdentity};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn object(tag: u8, size: usize, from: Option<PeerKey>, expires_at: Timestamp) -> StoredObject {
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
            payload_hash: sha256(&[&vec![tag; size]]),
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
            // As a node writes it: own submissions are hop 0, received ones hop 1.
            hop_count: u8::from(from.is_some()),
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
        let peer = PeerKey([9; 32]);
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

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let path = std::env::temp_dir().join(format!(
                "constellation-store-{tag}-{}-{nanos}",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn object_path(dir: &std::path::Path, id: &ObjectId) -> std::path::PathBuf {
        dir.join("objects")
            .join(format!("{}.cbor", hex::encode(id.as_bytes())))
    }

    #[test]
    fn file_store_round_trips_objects_and_seen_across_reopen() {
        let dir = TempDir::new("roundtrip");
        let peer = PeerKey([9; 32]);
        let held = object(1, 40, Some(peer), 1_000);
        let delivered = object(2, 5, None, 1_000).object_id;
        let gone = object(3, 5, None, 1_000);
        {
            let mut store = FileStore::open(dir.path(), StorePolicy::default()).expect("open");
            store.insert(held.clone()).expect("insert");
            store.mark_seen(delivered);
            store.insert(gone.clone()).expect("insert");
            assert!(store.remove(&gone.object_id).is_some());
            assert!(object_path(dir.path(), &held.object_id).is_file());
            assert!(!object_path(dir.path(), &gone.object_id).exists());
        }
        let store = FileStore::open(dir.path(), StorePolicy::default()).expect("reopen");
        assert_eq!(store.rejected_at_load(), 0);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&held.object_id), Some(&held));
        assert!(store.seen(&held.object_id));
        assert!(store.seen(&delivered));
        assert!(store.seen(&gone.object_id), "removed ids stay remembered");
        assert!(store.get(&gone.object_id).is_none());
        assert!(!store.seen(&object(4, 5, None, 1_000).object_id));
    }

    #[test]
    fn file_store_skips_corrupt_entries_at_load() {
        let dir = TempDir::new("corrupt");
        let good = object(1, 40, None, 1_000);
        let truncated = object(2, 40, None, 1_000);
        let tampered = object(3, 40, None, 1_000);
        {
            let mut store = FileStore::open(dir.path(), StorePolicy::default()).expect("open");
            store.insert(good.clone()).expect("insert");
            store.insert(truncated.clone()).expect("insert");
            store.insert(tampered.clone()).expect("insert");
        }
        let objects = dir.path().join("objects");
        // A write that never completed.
        let path = object_path(dir.path(), &truncated.object_id);
        let bytes = std::fs::read(&path).expect("read");
        std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("truncate");
        // A ciphertext byte flipped on disk: the signed commitment no longer holds.
        let path = object_path(dir.path(), &tampered.object_id);
        let mut bytes = std::fs::read(&path).expect("read");
        let pos = bytes
            .windows(40)
            .position(|w| w == tampered.ciphertext.as_slice())
            .expect("ciphertext is stored verbatim");
        bytes[pos] ^= 0x01;
        std::fs::write(&path, &bytes).expect("tamper");
        // Not CBOR at all, and larger than any frame could be.
        std::fs::write(objects.join("junk.cbor"), b"not an object").expect("junk");
        std::fs::write(objects.join("huge.cbor"), vec![0u8; MAX_RECORD_BYTES + 1]).expect("huge");
        // A torn seen-set write leaves a partial trailing id.
        let seen = dir.path().join("seen.bin");
        let mut bytes = std::fs::read(&seen).expect("read seen");
        bytes.extend_from_slice(&[1, 2, 3]);
        std::fs::write(&seen, &bytes).expect("tear seen");

        let store = FileStore::open(dir.path(), StorePolicy::default()).expect("reopen");
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&good.object_id), Some(&good));
        assert_eq!(store.rejected_at_load(), 5);
        // Complete seen entries survive the torn tail.
        assert!(store.seen(&good.object_id));
        assert!(store.seen(&truncated.object_id));
        assert!(store.seen(&tampered.object_id));
    }

    #[test]
    fn failed_write_rolls_back_duplicate_memory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("rollback");
        let held = object(1, 40, Some(PeerKey([9; 32])), 1_000);
        let mut store = FileStore::open(dir.path(), StorePolicy::default()).expect("open");
        let objects = dir.path().join("objects");
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        assert_eq!(store.insert(held.clone()), Err(StoreError::Io));
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(
            !store.seen(&held.object_id),
            "a refused object must not read as a duplicate"
        );
        assert_eq!(store.insert(held.clone()), Ok(()));
        assert!(store.seen(&held.object_id));
    }

    #[test]
    fn records_with_impossible_hop_state_are_skipped_at_load() {
        let dir = TempDir::new("hops");
        let relayed = object(1, 40, Some(PeerKey([9; 32])), 1_000);
        let own = object(2, 40, None, 1_000);
        {
            let mut store = FileStore::open(dir.path(), StorePolicy::default()).expect("open");
            store.insert(relayed.clone()).expect("insert");
            store.insert(own.clone()).expect("insert");
        }
        let rewrite = |o: &StoredObject, hop_count: u8| {
            let record = Record {
                envelope: o.envelope.clone(),
                ciphertext: o.ciphertext.clone(),
                hop_count,
                from: o.from,
                received_at: o.received_at,
            };
            std::fs::write(
                object_path(dir.path(), &o.object_id),
                minicbor::to_vec(&record).expect("encode"),
            )
            .expect("write");
        };
        rewrite(&relayed, 255); // beyond the envelope's max_hops
        rewrite(&own, 1); // a local submission (no handing-over peer) is hop 0
        let store = FileStore::open(dir.path(), StorePolicy::default()).expect("reopen");
        assert_eq!(store.len(), 0);
        assert_eq!(store.rejected_at_load(), 2);
    }

    #[test]
    fn largest_acceptable_frame_survives_reopen() {
        use crate::envelope::Frame;
        let dir = TempDir::new("max-size");
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 0, &mut rng);
        let ciphertext = vec![7u8; MAX_CIPHERTEXT_BYTES];
        let build = |type_len: usize| {
            let body = EnvelopeBody {
                version: 1,
                object_type: "t".repeat(type_len),
                creator: device.record().authorization,
                created_at: u64::MAX / 4,
                expires_at: u64::MAX / 2,
                audience: Audience {
                    user: device.user(),
                    device: device.id(),
                },
                payload_size: ciphertext.len() as u32,
                payload_hash: sha256(&[&ciphertext]),
                encryption: Encryption {
                    suite: SUITE_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
                    encapsulated_key: EncryptionKey([0; 32]),
                },
                routing: Routing {
                    max_hops: 2,
                    priority: 0,
                },
            };
            Envelope::sign(body, &device)
        };
        // Grow object_type to the largest wire frame that still fits
        // MAX_FRAME_BYTES (CBOR length heads can make exact equality unreachable).
        let frame_len = |envelope: &Envelope| {
            Frame::Object {
                envelope: envelope.clone(),
                ciphertext: ciphertext.clone(),
                hop_count: 1,
            }
            .encode()
            .len()
        };
        let mut type_len = 1;
        while frame_len(&build(type_len + 1)) <= MAX_FRAME_BYTES {
            type_len += (MAX_FRAME_BYTES - frame_len(&build(type_len))).max(1);
            while frame_len(&build(type_len)) > MAX_FRAME_BYTES {
                type_len -= 1;
            }
        }
        let envelope = build(type_len);
        let wire = Frame::Object {
            envelope: envelope.clone(),
            ciphertext: ciphertext.clone(),
            hop_count: 1,
        }
        .encode();
        assert!(
            wire.len() + 2 >= MAX_FRAME_BYTES,
            "frame too small: {}",
            wire.len()
        );
        assert!(
            Frame::decode(&wire).is_ok(),
            "the frame is acceptable on the wire"
        );
        let held = StoredObject {
            object_id: envelope.object_id(),
            envelope,
            ciphertext,
            hop_count: 1,
            from: Some(PeerKey([9; 32])),
            received_at: u64::MAX / 2,
        };
        let policy = StorePolicy::default();
        {
            let mut store = FileStore::open(dir.path(), policy.clone()).expect("open");
            store.insert(held.clone()).expect("insert");
        }
        let store = FileStore::open(dir.path(), policy).expect("reopen");
        assert_eq!(store.rejected_at_load(), 0);
        assert_eq!(store.get(&held.object_id), Some(&held));
    }
}
