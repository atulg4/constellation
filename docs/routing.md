# Routing

Constellation routing assumes intermittent connectivity and delayed acknowledgements.

## Delivery States

- submitted
- locally accepted
- direct-send attempted
- custody accepted by peer
- forwarded
- delivered
- expired
- rejected
- revoked
- unknown

## Mission 001 Routing

Mission 001 should implement only:

1. direct delivery when recipient is present;
2. one-hop custody forwarding when an authorized carrier encounters a recipient;
3. TTL and hop-limit enforcement;
4. duplicate suppression;
5. signed delivery/custody receipts.

## Later Routing

Later missions can evaluate:

- destination-aware forwarding;
- controlled replication;
- contact-history routing;
- social/trust graph hints;
- opportunistic relays;
- multipath transfer;
- gossip with strict budgets;
- contact plans for predictable links;
- relay/gateway policy negotiation.

Naive flooding is explicitly rejected as a default architecture.

