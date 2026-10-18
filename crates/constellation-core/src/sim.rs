//! Deterministic in-process network for Mission 001 scenarios.
//!
//! Nodes are keyed by device id in a `BTreeMap`, links are an ordered set,
//! frames travel through a FIFO queue, and time only moves when told to.
//! The same seed therefore always produces the same run. Frames are
//! encoded to bytes and decoded again on delivery so the wire codec and its
//! size bound are exercised on every transfer.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::envelope::{Frame, ObjectId};
use crate::identity::{DeviceId, DeviceRecord};
use crate::node::{Node, PeerInfo, SubmitError};
use crate::transport::{Capabilities, Locality};
use crate::{Timestamp, MAX_FRAME_BYTES};

/// What the simulated link reports to routing.
pub const SIM_CAPABILITIES: Capabilities = Capabilities {
    name: "simulated",
    locality: Locality::Simulated,
    max_frame_bytes: MAX_FRAME_BYTES,
    background_viable: true,
    link_encrypted: false,
};

struct Packet {
    from: DeviceId,
    to: DeviceId,
    bytes: Vec<u8>,
}

/// The simulated world: nodes, links, in-flight frames, and a clock.
pub struct Simulator {
    now: Timestamp,
    rng: ChaCha20Rng,
    nodes: BTreeMap<DeviceId, Node>,
    peers: BTreeMap<DeviceId, PeerInfo>,
    links: BTreeSet<(DeviceId, DeviceId)>,
    queue: VecDeque<Packet>,
    dropped: usize,
}

impl Simulator {
    /// A world starting at wall clock `now` with a seeded RNG.
    pub fn new(now: Timestamp, seed: u64) -> Self {
        Self {
            now,
            rng: ChaCha20Rng::seed_from_u64(seed),
            nodes: BTreeMap::new(),
            peers: BTreeMap::new(),
            links: BTreeSet::new(),
            queue: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Current simulated time.
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Frames dropped for lack of a link, a missing node, or a bad encoding.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// Adds a node; its peer description is what others see on contact.
    pub fn add_node(&mut self, node: Node) {
        let id = node.id();
        self.peers.insert(id, node.peer_info());
        self.nodes.insert(id, node);
    }

    /// Borrows a node. Panics if `id` is unknown, which is a test bug.
    pub fn node(&self, id: &DeviceId) -> &Node {
        self.nodes.get(id).expect("unknown node in simulation")
    }

    /// Mutably borrows a node. Panics if `id` is unknown.
    pub fn node_mut(&mut self, id: &DeviceId) -> &mut Node {
        self.nodes.get_mut(id).expect("unknown node in simulation")
    }

    /// Has `from` create an object for `to` using the simulation clock and RNG.
    pub fn submit(
        &mut self,
        from: &DeviceId,
        to: &DeviceRecord,
        plaintext: &[u8],
        ttl_ms: u64,
    ) -> Result<ObjectId, SubmitError> {
        let now = self.now;
        let rng = &mut self.rng;
        self.nodes
            .get_mut(from)
            .expect("unknown node in simulation")
            .submit(to, plaintext, ttl_ms, now, rng)
    }

    /// Brings two nodes into contact; both get to offer objects.
    pub fn connect(&mut self, a: &DeviceId, b: &DeviceId) {
        self.links.insert(link(a, b));
        self.offer(a, b);
        self.offer(b, a);
    }

    fn offer(&mut self, from: &DeviceId, to: &DeviceId) {
        let Some(peer) = self.peers.get(to).cloned() else {
            return;
        };
        let now = self.now;
        let frames = match self.nodes.get_mut(from) {
            Some(node) => node.on_connect(&peer, now),
            None => return,
        };
        for frame in frames {
            self.enqueue(*from, *to, &frame);
        }
    }

    /// Breaks the link; frames still in flight between them are dropped.
    pub fn disconnect(&mut self, a: &DeviceId, b: &DeviceId) {
        self.links.remove(&link(a, b));
    }

    /// Removes a node from the world entirely, as if it powered off.
    pub fn remove(&mut self, id: &DeviceId) {
        self.nodes.remove(id);
        self.peers.remove(id);
        self.links.retain(|(x, y)| x != id && y != id);
    }

    /// Queues an arbitrary frame as if `from` had sent it to `to`.
    pub fn inject(&mut self, from: &DeviceId, to: &DeviceId, frame: Frame) {
        self.enqueue(*from, *to, &frame);
    }

    fn enqueue(&mut self, from: DeviceId, to: DeviceId, frame: &Frame) {
        self.queue.push_back(Packet {
            from,
            to,
            bytes: frame.encode(),
        });
    }

    /// Moves the clock forward.
    pub fn advance(&mut self, ms: u64) {
        self.now += ms;
    }

    /// Delivers frames in order until nothing is in flight.
    pub fn run_until_idle(&mut self) {
        while let Some(packet) = self.queue.pop_front() {
            if !self.links.contains(&link(&packet.from, &packet.to)) {
                self.dropped += 1;
                continue;
            }
            let Some(sender) = self.peers.get(&packet.from).cloned() else {
                self.dropped += 1;
                continue;
            };
            let Ok(frame) = Frame::decode(&packet.bytes) else {
                self.dropped += 1;
                continue;
            };
            let now = self.now;
            let replies = match self.nodes.get_mut(&packet.to) {
                Some(node) => node.handle_frame(&sender, frame, now),
                None => {
                    self.dropped += 1;
                    continue;
                }
            };
            for reply in replies {
                self.enqueue(packet.to, packet.from, &reply);
            }
        }
    }
}

fn link(a: &DeviceId, b: &DeviceId) -> (DeviceId, DeviceId) {
    if a <= b {
        (*a, *b)
    } else {
        (*b, *a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ContactBook, DeviceIdentity, UserIdentity};
    use crate::node::Policy;

    fn node(seed: u8) -> Node {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let user = UserIdentity::generate(&mut rng);
        let device = DeviceIdentity::generate(&user, 0, &mut rng);
        Node::new(device, ContactBook::new(), Policy::default())
    }

    #[test]
    fn frames_without_a_link_are_dropped() {
        let mut sim = Simulator::new(0, 1);
        let a = node(1);
        let b = node(2);
        let (ida, idb) = (a.id(), b.id());
        sim.add_node(a);
        sim.add_node(b);
        sim.inject(
            &ida,
            &idb,
            Frame::Ack {
                object_id: ObjectId([0; 32]),
                outcome: crate::envelope::AckOutcome::Delivered,
            },
        );
        sim.run_until_idle();
        assert_eq!(sim.dropped(), 1);
        sim.connect(&ida, &idb);
        sim.inject(
            &ida,
            &idb,
            Frame::Ack {
                object_id: ObjectId([0; 32]),
                outcome: crate::envelope::AckOutcome::Delivered,
            },
        );
        sim.run_until_idle();
        assert_eq!(sim.dropped(), 1);
    }

    #[test]
    fn same_seed_same_run() {
        let ids = |seed| {
            let mut sim = Simulator::new(0, seed);
            let a = node(1);
            let b = node(2);
            let ida = a.id();
            let rb = b.record();
            sim.add_node(a);
            sim.add_node(b);
            sim.submit(&ida, &rb, b"x", 10).expect("submit")
        };
        assert_eq!(ids(7), ids(7));
        assert_ne!(ids(7), ids(8));
    }
}
