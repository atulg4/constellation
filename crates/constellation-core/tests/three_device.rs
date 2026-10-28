//! Mission 001 acceptance tests: deterministic three-device store-carry-forward.
//!
//! A creates an encrypted, signed object for C. A meets B and hands custody
//! over. A disappears. B later meets C and forwards. C verifies and decrypts.
//! Every rejection path in `missions/001-core-runtime.md` is exercised here.

use constellation_core::crypto;
use constellation_core::envelope::{AckOutcome, Audience, Envelope, Frame, ObjectId};
use constellation_core::identity::{ContactBook, DeviceIdentity, DeviceRecord, UserIdentity};
use constellation_core::node::{Node, ObjectState, Policy, RejectReason, StorePolicy, SubmitError};
use constellation_core::sim::Simulator;
use constellation_core::{Timestamp, MAX_PLAINTEXT_BYTES};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const T0: Timestamp = 1_700_000_000_000; // fixed wall clock, ms since Unix epoch
const ONE_HOUR: u64 = 3_600_000;
const SECRET: &[u8] = b"meet at the north gate at dawn";

struct Party {
    device: DeviceIdentity,
    record: DeviceRecord,
}

fn party(seed: u8) -> Party {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let user = UserIdentity::generate(&mut rng);
    let device = DeviceIdentity::generate(&user, T0, &mut rng);
    let record = device.record();
    Party { device, record }
}

/// Everyone trusts everyone's user key, as if contacts were verified out of band.
fn contacts(parties: &[&Party]) -> ContactBook {
    let mut book = ContactBook::new();
    for p in parties {
        book.trust_user(p.record.user);
    }
    book
}

fn carrier_policy() -> Policy {
    Policy {
        accept_custody: true,
        ..Policy::default()
    }
}

fn endpoint_policy() -> Policy {
    Policy {
        accept_custody: false,
        ..Policy::default()
    }
}

/// Standard cast: A (sender, seed 1), B (carrier, seed 2), C (recipient, seed 3).
fn cast() -> (Simulator, Party, Party, Party) {
    let a = party(1);
    let b = party(2);
    let c = party(3);
    let book = contacts(&[&a, &b, &c]);
    let mut sim = Simulator::new(T0, 42);
    sim.add_node(Node::new(a.device.clone(), book.clone(), endpoint_policy()));
    sim.add_node(Node::new(b.device.clone(), book.clone(), carrier_policy()));
    sim.add_node(Node::new(c.device.clone(), book, endpoint_policy()));
    (sim, a, b, c)
}

fn states(sim: &Simulator, who: &Party) -> Vec<ObjectState> {
    sim.node(&who.record.device)
        .events()
        .iter()
        .map(|e| e.state.clone())
        .collect()
}

#[test]
fn happy_path_a_to_b_custody_then_b_to_c_delivery() {
    let (mut sim, a, b, c) = cast();
    let id = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");

    // Phase 1: A meets B. B accepts custody of an opaque object.
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    assert_eq!(states(&sim, &b), vec![ObjectState::CustodyAccepted]);
    assert_eq!(
        states(&sim, &a),
        vec![ObjectState::Submitted, ObjectState::Forwarded]
    );
    assert!(sim.node(&c.record.device).inbox().is_empty());

    // A disappears entirely.
    sim.disconnect(&a.record.device, &b.record.device);
    sim.remove(&a.record.device);
    sim.advance(10 * 60_000);

    // Phase 2: B meets C. B forwards; C verifies and decrypts.
    sim.connect(&b.record.device, &c.record.device);
    sim.run_until_idle();

    let inbox = sim.node(&c.record.device).inbox();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].object_id, id);
    assert_eq!(inbox[0].plaintext, SECRET);
    assert_eq!(inbox[0].creator_user, a.record.user);
    assert_eq!(inbox[0].creator_device, a.record.device);
    assert_eq!(states(&sim, &c), vec![ObjectState::Delivered]);
    assert_eq!(
        states(&sim, &b),
        vec![ObjectState::CustodyAccepted, ObjectState::Delivered]
    );
    // B no longer holds the object once delivery is acknowledged.
    assert!(sim.node(&b.record.device).custody().is_empty());
}

#[test]
fn carrier_never_sees_plaintext_and_cannot_decrypt() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();

    let held = sim.node(&b.record.device).custody();
    assert_eq!(held.len(), 1);
    let stored = &held[0];
    assert!(
        !contains(&stored.ciphertext, SECRET),
        "plaintext leaked into carrier store"
    );
    let canonical = stored.envelope.canonical_bytes();
    assert!(
        !contains(&canonical, SECRET),
        "plaintext leaked into envelope"
    );
    assert!(crypto::open_payload(&b.device, &stored.envelope, &stored.ciphertext).is_err());
    // The intended recipient can decrypt the very same bytes.
    assert_eq!(
        crypto::open_payload(&c.device, &stored.envelope, &stored.ciphertext).expect("open"),
        SECRET
    );
    // Lifecycle events never carry payload or secrets.
    let rendered = format!("{:?}", sim.node(&b.record.device).events());
    assert!(!rendered.contains("north gate"));
}

#[test]
fn recipient_rejects_tampered_envelope() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();

    let mut forged = stored.envelope.clone();
    forged.body.expires_at += ONE_HOUR; // extend TTL without re-signing
    sim.connect(&b.record.device, &c.record.device);
    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: forged,
            ciphertext: stored.ciphertext.clone(),
            hop_count: 2,
        },
    );
    sim.run_until_idle();
    assert!(states(&sim, &c).contains(&ObjectState::Rejected(RejectReason::BadSignature)));
}

#[test]
fn recipient_rejects_corrupted_ciphertext() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();

    let mut corrupted = stored.ciphertext.clone();
    corrupted[3] ^= 0x01;
    sim.link(&b.record.device, &c.record.device);
    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: stored.envelope.clone(),
            ciphertext: corrupted,
            hop_count: 2,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::PayloadHashMismatch)]
    );
    assert!(sim.node(&c.record.device).inbox().is_empty());
    // B still holds the genuine copy and delivers it afterwards.
    assert_eq!(sim.node(&b.record.device).custody().len(), 1);
}

#[test]
fn recipient_rejects_object_addressed_to_another_user() {
    let (mut sim, a, _b, c) = cast();
    let stranger = party(9);
    // Honest signature, but the audience names C's device under the wrong user.
    let audience = Audience {
        user: stranger.record.user,
        device: c.record.device,
    };
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let (envelope, ciphertext) = sim
        .node(&a.record.device)
        .build_object(
            audience,
            &c.record.encryption_key,
            SECRET,
            ONE_HOUR,
            T0,
            &mut rng,
        )
        .expect("build");
    sim.connect(&a.record.device, &c.record.device);
    sim.inject(
        &a.record.device,
        &c.record.device,
        Frame::Object {
            envelope,
            ciphertext,
            hop_count: 1,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::UnauthorizedRecipient)]
    );
}

#[test]
fn endpoint_refuses_custody_of_objects_for_others() {
    let (mut sim, a, _b, c) = cast();
    let d = party(4);
    sim.submit(&a.record.device, &d.record, SECRET, ONE_HOUR)
        .expect("submit");
    // A meets C directly; C is not the audience and does not carry for others.
    sim.connect(&a.record.device, &c.record.device);
    sim.run_until_idle();
    assert!(
        states(&sim, &c).is_empty(),
        "C must not even be offered custody"
    );
    assert_eq!(states(&sim, &a), vec![ObjectState::Submitted]);
}

#[test]
fn expired_objects_are_dropped_by_carrier_and_rejected_by_recipient() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, 10_000)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();

    sim.advance(10_000); // now == expires_at: expired
    sim.connect(&b.record.device, &c.record.device);
    sim.run_until_idle();
    assert!(sim.node(&c.record.device).inbox().is_empty());
    assert_eq!(
        states(&sim, &b),
        vec![ObjectState::CustodyAccepted, ObjectState::Expired]
    );
    assert!(sim.node(&b.record.device).custody().is_empty());

    // A stale copy pushed directly at C is rejected too.
    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: stored.ciphertext,
            hop_count: 2,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::Expired)]
    );
}

#[test]
fn duplicate_delivery_is_idempotent() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();
    sim.connect(&b.record.device, &c.record.device);
    sim.run_until_idle();
    assert_eq!(sim.node(&c.record.device).inbox().len(), 1);

    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: stored.ciphertext,
            hop_count: 2,
        },
    );
    sim.run_until_idle();
    assert_eq!(sim.node(&c.record.device).inbox().len(), 1);
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Delivered, ObjectState::Duplicate]
    );
}

#[test]
fn hop_limit_blocks_second_custody_hop() {
    let (mut sim, a, b, c) = cast();
    let x = party(5);
    let book = contacts(&[&a, &b, &c, &x]);
    sim.add_node(Node::new(x.device.clone(), book, carrier_policy()));
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    sim.remove(&a.record.device);

    // B meets another carrier X. One custody hop only: B must not re-delegate.
    sim.connect(&b.record.device, &x.record.device);
    sim.run_until_idle();
    assert!(states(&sim, &x).is_empty());
    assert_eq!(sim.node(&b.record.device).custody().len(), 1);

    // A frame claiming an over-limit hop count is rejected outright.
    let stored = sim.node(&b.record.device).custody()[0].clone();
    sim.link(&b.record.device, &c.record.device);
    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: stored.ciphertext,
            hop_count: 3,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::HopLimitExceeded)]
    );
}

#[test]
fn untrusted_creator_is_rejected() {
    let (mut sim, a, _b, c) = cast();
    let outsider = party(6);
    // The outsider knows everyone, but nobody has verified the outsider.
    let book = contacts(&[&a, &c, &outsider]);
    sim.add_node(Node::new(outsider.device.clone(), book, endpoint_policy()));
    sim.submit(&outsider.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&outsider.record.device, &c.record.device);
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::UntrustedCreator)]
    );
}

#[test]
fn unsupported_version_is_rejected_before_anything_else() {
    let (mut sim, a, _b, c) = cast();
    let mut rng = ChaCha20Rng::from_seed([8; 32]);
    let (envelope, ciphertext) = sim
        .node(&a.record.device)
        .build_object(
            Audience {
                user: c.record.user,
                device: c.record.device,
            },
            &c.record.encryption_key,
            SECRET,
            ONE_HOUR,
            T0,
            &mut rng,
        )
        .expect("build");
    let mut body = envelope.body.clone();
    body.version = 2;
    let resigned = Envelope::sign(body, &a.device);
    sim.connect(&a.record.device, &c.record.device);
    sim.inject(
        &a.record.device,
        &c.record.device,
        Frame::Object {
            envelope: resigned,
            ciphertext,
            hop_count: 1,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Rejected(RejectReason::UnsupportedVersion)]
    );
}

#[test]
fn carrier_enforces_store_quota() {
    let a = party(1);
    let b = party(2);
    let c = party(3);
    let book = contacts(&[&a, &b, &c]);
    let tiny = Policy {
        accept_custody: true,
        store: StorePolicy {
            max_objects: 1,
            ..StorePolicy::default()
        },
        ..Policy::default()
    };
    let mut sim = Simulator::new(T0, 1);
    sim.add_node(Node::new(a.device.clone(), book.clone(), endpoint_policy()));
    sim.add_node(Node::new(b.device.clone(), book, tiny));
    sim.submit(&a.record.device, &c.record, b"first", ONE_HOUR)
        .expect("submit");
    sim.submit(&a.record.device, &c.record, b"second", ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &b),
        vec![
            ObjectState::CustodyAccepted,
            ObjectState::Rejected(RejectReason::QuotaExceeded)
        ]
    );
    // A keeps the rejected object pending for a later carrier.
    assert_eq!(sim.node(&a.record.device).custody().len(), 1);
}

#[test]
fn oversized_payload_is_refused_at_submit() {
    let (mut sim, a, _b, c) = cast();
    let big = vec![0u8; MAX_PLAINTEXT_BYTES + 1];
    assert!(sim
        .submit(&a.record.device, &c.record, &big, ONE_HOUR)
        .is_err());
    let max = vec![0u8; MAX_PLAINTEXT_BYTES];
    assert!(sim
        .submit(&a.record.device, &c.record, &max, ONE_HOUR)
        .is_ok());
}

#[test]
fn object_id_is_stable_across_nodes_and_derived_from_ciphertext() {
    let (mut sim, a, b, c) = cast();
    let id = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();
    assert_eq!(stored.object_id, id);
    assert_eq!(stored.envelope.object_id(), id);
    assert_eq!(ObjectId::from(stored.envelope.object_id().as_bytes()), id);
    // Same plaintext submitted again yields a different id (fresh HPKE encapsulation).
    let again = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    assert_ne!(again, id);
}

#[test]
fn carrier_survives_restart() {
    let dir = TempDir::new("carrier-restart");
    let a = party(1);
    let b = party(2);
    let c = party(3);
    let x = party(4);
    let book = contacts(&[&a, &b, &c, &x]);
    let mut sim = Simulator::new(T0, 42);
    sim.add_node(Node::new(a.device.clone(), book.clone(), endpoint_policy()));
    sim.add_node(
        Node::persistent(b.device.clone(), book.clone(), carrier_policy(), dir.path())
            .expect("open store"),
    );
    sim.add_node(Node::new(c.device.clone(), book.clone(), endpoint_policy()));
    sim.add_node(Node::new(x.device.clone(), book.clone(), endpoint_policy()));
    let id = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");

    // A -> B custody, then A disappears.
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    assert_eq!(states(&sim, &b), vec![ObjectState::CustodyAccepted]);
    let stored = sim.node(&b.record.device).custody()[0].clone();
    sim.remove(&a.record.device);

    // B powers off: its Node is dropped and only the directory remains.
    sim.remove(&b.record.device);
    sim.advance(10 * 60_000);

    // B restarts from the same directory with the same device identity.
    let rebuilt = Node::persistent(b.device.clone(), book, carrier_policy(), dir.path())
        .expect("reopen store");
    assert_eq!(rebuilt.custody().len(), 1);
    assert_eq!(*rebuilt.custody()[0], stored);
    assert!(rebuilt.events().is_empty(), "events are process-local");
    sim.add_node(rebuilt);

    // A re-sent copy, before B has met C, is recognised from the persisted seen set.
    sim.connect(&x.record.device, &b.record.device);
    sim.inject(
        &x.record.device,
        &b.record.device,
        Frame::Object {
            envelope: stored.envelope.clone(),
            ciphertext: stored.ciphertext.clone(),
            hop_count: 1,
        },
    );
    sim.run_until_idle();
    assert_eq!(states(&sim, &b), vec![ObjectState::Duplicate]);
    assert_eq!(sim.node(&b.record.device).custody().len(), 1);

    // B -> C delivery.
    sim.connect(&b.record.device, &c.record.device);
    sim.run_until_idle();
    let inbox = sim.node(&c.record.device).inbox();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].object_id, id);
    assert_eq!(inbox[0].plaintext, SECRET);
    assert_eq!(
        states(&sim, &b),
        vec![ObjectState::Duplicate, ObjectState::Delivered]
    );
    assert!(sim.node(&b.record.device).custody().is_empty());
    let on_disk = std::fs::read_dir(dir.path().join("objects"))
        .expect("objects dir")
        .count();
    assert_eq!(on_disk, 0, "delivered objects leave no bytes behind");

    // One more restart: nothing held, the id is still remembered.
    sim.remove(&b.record.device);
    let again = Node::persistent(
        b.device.clone(),
        contacts(&[&a, &b, &c]),
        carrier_policy(),
        dir.path(),
    )
    .expect("reopen store");
    assert!(again.custody().is_empty());
    sim.add_node(again);
    sim.connect(&x.record.device, &b.record.device);
    sim.inject(
        &x.record.device,
        &b.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: stored.ciphertext,
            hop_count: 1,
        },
    );
    sim.run_until_idle();
    assert_eq!(states(&sim, &b), vec![ObjectState::Duplicate]);
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        Self(std::env::temp_dir().join(format!(
            "constellation-{tag}-{}-{nanos}",
            std::process::id()
        )))
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---- Review hardening (Codex review of PR #3) ----

#[test]
fn tampered_recipient_record_is_refused_at_submit() {
    let (mut sim, a, _b, c) = cast();
    let attacker = party(9);
    let mut forged = c.record.clone();
    forged.encryption_key = attacker.record.encryption_key;
    assert_eq!(
        sim.submit(&a.record.device, &forged, SECRET, ONE_HOUR),
        Err(SubmitError::InvalidRecipient)
    );
    let mut reassigned = c.record.clone();
    reassigned.user = attacker.record.user;
    assert_eq!(
        sim.submit(&a.record.device, &reassigned, SECRET, ONE_HOUR),
        Err(SubmitError::InvalidRecipient)
    );
    assert!(sim.node(&a.record.device).custody().is_empty());
}

#[test]
fn carrier_cannot_relaunch_custody_as_a_first_hop() {
    let (mut sim, a, b, c) = cast();
    let x = party(5);
    sim.add_node(Node::new(
        x.device.clone(),
        contacts(&[&a, &b, &c, &x]),
        carrier_policy(),
    ));
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();
    // B resets the hop count and offers A's object to X as if it were the creator.
    sim.link(&b.record.device, &x.record.device);
    sim.inject(
        &b.record.device,
        &x.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: stored.ciphertext,
            hop_count: 1,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &x),
        vec![ObjectState::Rejected(RejectReason::CustodyNotFromCreator)]
    );
    assert!(sim.node(&x.record.device).custody().is_empty());
}

#[test]
fn forged_acknowledgements_do_not_destroy_custody() {
    let (mut sim, a, b, c) = cast();
    let x = party(5);
    sim.add_node(Node::new(
        x.device.clone(),
        contacts(&[&a, &b, &c, &x]),
        endpoint_policy(),
    ));
    let id = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    // X learned the id and claims delivery and custody to B; B never offered X anything.
    sim.link(&x.record.device, &b.record.device);
    for outcome in [
        AckOutcome::Delivered,
        AckOutcome::Duplicate,
        AckOutcome::CustodyAccepted,
    ] {
        sim.inject(
            &x.record.device,
            &b.record.device,
            Frame::Ack {
                object_id: id,
                outcome,
            },
        );
    }
    sim.run_until_idle();
    assert_eq!(sim.node(&b.record.device).custody().len(), 1);
    assert_eq!(states(&sim, &b), vec![ObjectState::CustodyAccepted]);
}

#[test]
fn delivery_ack_must_come_from_the_audience_device() {
    let (mut sim, a, b, c) = cast();
    let id = sim
        .submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    // A offered custody to B, so B may say CustodyAccepted, but never Delivered.
    sim.link(&a.record.device, &b.record.device);
    sim.offer(&a.record.device, &b.record.device);
    sim.inject(
        &b.record.device,
        &a.record.device,
        Frame::Ack {
            object_id: id,
            outcome: AckOutcome::Delivered,
        },
    );
    // Drop the genuine Object frame A queued: deliver only the forged ack.
    sim.drop_frames_to(&b.record.device);
    sim.run_until_idle();
    assert_eq!(sim.node(&a.record.device).custody().len(), 1);
    let _ = c;
}

#[test]
fn submit_purges_expired_objects_before_enforcing_quota() {
    let a = party(1);
    let c = party(3);
    let book = contacts(&[&a, &c]);
    let tiny = Policy {
        store: StorePolicy {
            max_objects: 1,
            ..StorePolicy::default()
        },
        ..endpoint_policy()
    };
    let mut sim = Simulator::new(T0, 1);
    sim.add_node(Node::new(a.device.clone(), book, tiny));
    sim.submit(&a.record.device, &c.record, b"first", 1_000)
        .expect("submit");
    sim.advance(1_000);
    assert!(sim
        .submit(&a.record.device, &c.record, b"second", 1_000)
        .is_ok());
    assert_eq!(sim.node(&a.record.device).custody().len(), 1);
}

#[test]
fn inbox_is_bounded_and_can_be_drained() {
    let a = party(1);
    let c = party(3);
    let book = contacts(&[&a, &c]);
    let mut sim = Simulator::new(T0, 1);
    sim.add_node(Node::new(a.device.clone(), book.clone(), endpoint_policy()));
    sim.add_node(Node::new(
        c.device.clone(),
        book,
        Policy {
            max_inbox: 1,
            ..endpoint_policy()
        },
    ));
    sim.submit(&a.record.device, &c.record, b"one", ONE_HOUR)
        .expect("submit");
    sim.submit(&a.record.device, &c.record, b"two", ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &c.record.device);
    sim.run_until_idle();
    assert_eq!(sim.node(&c.record.device).inbox().len(), 1);
    assert!(states(&sim, &c).contains(&ObjectState::Rejected(RejectReason::QuotaExceeded)));
    // The refused object stays with A; draining the inbox makes room.
    let drained = sim.node_mut(&c.record.device).take_inbox();
    assert_eq!(drained.len(), 1);
    assert!(sim.node(&c.record.device).inbox().is_empty());
    sim.disconnect(&a.record.device, &c.record.device);
    sim.connect(&a.record.device, &c.record.device);
    sim.run_until_idle();
    assert_eq!(sim.node(&c.record.device).inbox().len(), 1);
    assert!(sim.node(&a.record.device).custody().is_empty());
}

#[test]
fn custody_is_offered_only_to_trusted_carriers() {
    let a = party(1);
    let c = party(3);
    let stranger = party(7);
    let mut sim = Simulator::new(T0, 1);
    // A trusts C but not the stranger, who advertises that it carries for anyone.
    sim.add_node(Node::new(
        a.device.clone(),
        contacts(&[&a, &c]),
        endpoint_policy(),
    ));
    sim.add_node(Node::new(
        stranger.device.clone(),
        contacts(&[&a, &c, &stranger]),
        carrier_policy(),
    ));
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &stranger.record.device);
    sim.run_until_idle();
    assert!(states(&sim, &stranger).is_empty());
    assert_eq!(sim.node(&a.record.device).custody().len(), 1);
}

#[test]
fn known_object_is_suppressed_before_any_verification() {
    let (mut sim, a, b, c) = cast();
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    let stored = sim.node(&b.record.device).custody()[0].clone();
    sim.connect(&b.record.device, &c.record.device);
    sim.run_until_idle();
    // A replay with garbage ciphertext is recognised by id and dropped as a duplicate
    // without hashing or decrypting anything.
    sim.inject(
        &b.record.device,
        &c.record.device,
        Frame::Object {
            envelope: stored.envelope,
            ciphertext: vec![0xff; 8],
            hop_count: 2,
        },
    );
    sim.run_until_idle();
    assert_eq!(
        states(&sim, &c),
        vec![ObjectState::Delivered, ObjectState::Duplicate]
    );
    assert_eq!(sim.node(&c.record.device).inbox().len(), 1);
}

#[test]
fn carrier_store_never_holds_raw_peer_ids() {
    let dir = TempDir::new("no-raw-peer-ids");
    let (mut sim, a, b, c) = cast();
    let book = contacts(&[&a, &b, &c]);
    sim.remove(&b.record.device);
    sim.add_node(
        Node::persistent(b.device.clone(), book, carrier_policy(), dir.path()).expect("open store"),
    );
    sim.submit(&a.record.device, &c.record, SECRET, ONE_HOUR)
        .expect("submit");
    sim.connect(&a.record.device, &b.record.device);
    sim.run_until_idle();
    assert_eq!(sim.node(&b.record.device).custody().len(), 1);
    // The handing-over device (A) is also the creator, and its id legitimately
    // appears inside the signed envelope. What must not appear is a separate
    // raw copy recorded as "who handed this over": count occurrences.
    let envelope_copies = {
        let stored = sim.node(&b.record.device).custody()[0].clone();
        count(
            &stored.envelope.canonical_bytes(),
            a.record.device.as_bytes(),
        )
    };
    let mut on_disk = 0;
    for entry in walk(dir.path()) {
        on_disk += count(
            &std::fs::read(entry).expect("read"),
            a.record.device.as_bytes(),
        );
    }
    assert_eq!(
        on_disk, envelope_copies,
        "raw handing-over peer id persisted"
    );
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}
