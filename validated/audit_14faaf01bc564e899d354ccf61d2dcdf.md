### Title
Stale `ProtocolStateIDCache` Not Refreshed on Mid-Epoch Node Ejection Allows Ejected Nodes to Bypass Connection Gating - (`network/p2p/cache/protocol_state_provider.go`)

---

### Summary

`ProtocolStateIDCache` caches the Flow identity table and only refreshes it on epoch-phase transition events (`EpochTransition`, `EpochSetupPhaseStarted`, `EpochCommittedPhaseStarted`). The Flow protocol supports mid-epoch node ejection via `EjectNode` service events, but no corresponding cache-refresh event exists. As a result, after a node is ejected mid-epoch, the cache continues to serve the stale pre-ejection identity (with `Ejected = false`). Every security gate that reads from this cache — the connection gater's `notEjectedPeerFilter`, `ConnGater.InterceptPeerDial`, `ConnGater.InterceptSecured`, and `HasValidFlowIdentity` in gossip scoring — will incorrectly treat the ejected node as a valid participant, allowing it to establish new connections and continue participating in the p2p network.

---

### Finding Description

`ProtocolStateIDCache` is the authoritative in-process identity provider used by the networking layer. It is initialized once and then updated only when one of three epoch-phase events fires: [1](#0-0) 

No callback exists for node ejection. The `IdentityDeltas` gadget — which is the parallel event-driven structure for identity changes — carries an explicit TODO acknowledging this gap: [2](#0-1) 

When a node is ejected mid-epoch via an `EjectNode` service event, the ejection is correctly applied to the on-chain protocol state by the `ejector` in the state machine: [3](#0-2) 

However, `ProtocolStateIDCache` is never notified. Its `update()` method, which re-reads the identity table from the protocol state, is never called: [4](#0-3) 

All consumers of the cache therefore read the stale pre-ejection identity. The `notEjectedPeerFilter` used by the connection gater calls `idProvider.ByPeerID(p)` and checks `id.IsEjected()`: [5](#0-4) 

This filter is installed on both `InterceptPeerDial` (outbound) and `InterceptSecured` (inbound) callbacks of `ConnGater`: [6](#0-5) 

`HasValidFlowIdentity`, used in gossip scoring, reads from the same stale cache: [7](#0-6) 

Because the cache is never refreshed on ejection, all of these checks return "not ejected" for the ejected node until the next epoch-phase transition occurs — which may be weeks away.

---

### Impact Explanation

An ejected node (ejected on-chain via a finalized `EjectNode` service event) can continue to:

1. Dial other Flow nodes and have the connection accepted by `ConnGater.InterceptPeerDial` and `ConnGater.InterceptSecured`, because the stale cache still shows `Ejected = false`.
2. Pass gossip scoring validation in `HasValidFlowIdentity`, allowing it to send and receive gossip messages.
3. Remain a peer in the p2p overlay for the remainder of the epoch, bypassing the ejection mechanism entirely.

The ejection mechanism is the protocol's primary tool for isolating a confirmed-malicious node from the network. Bypassing it allows the ejected node to continue sending malicious messages, influencing gossip scoring, and potentially disrupting protocol engines that rely on the p2p layer.

---

### Likelihood Explanation

Node ejection via `EjectNode` service events is a supported, on-chain-finalized protocol operation. The gap is structural: the `ProtocolStateIDCache` has no ejection callback, and the `IdentityDeltas` gadget explicitly documents the missing hook. Any epoch in which a node is ejected mid-epoch triggers this condition. The ejected node operator retains their private networking key and can immediately attempt reconnection after ejection is finalized.

---

### Recommendation

Add a `BlockFinalized` or dedicated ejection callback to `ProtocolStateIDCache` so that the cache is refreshed whenever a block finalizing an `EjectNode` service event is processed. Alternatively, implement the missing ejection event in `IdentityDeltas` (as noted by the existing TODO) and subscribe `ProtocolStateIDCache` to it. The `IdentityDeltas` gadget already has the correct structure: [8](#0-7) 

A corresponding `EjectNode` callback should be added there and wired into `ProtocolStateIDCache.update()`.

---

### Proof of Concept

1. Node A is a staked Consensus node. Its identity is loaded into `ProtocolStateIDCache` at startup.
2. A block is finalized that seals an execution result containing an `EjectNode` service event for Node A's `NodeID`.
3. The protocol state machine marks Node A as `Ejected = true` in the on-chain state via `ejector.Eject()`.
4. No epoch-phase transition event fires (the epoch is mid-staking-phase).
5. `ProtocolStateIDCache.update()` is never called; the cache still holds Node A's identity with `Ejected = false`.
6. Node A dials Node B. `ConnGater.InterceptPeerDial` on Node B calls `notEjectedPeerFilter`, which calls `idProvider.ByPeerID(nodeA_peerID)`. The cache returns the stale identity with `Ejected = false`. The filter returns `nil` (no error). The connection is accepted.
7. Node A is now connected to Node B and can send arbitrary p2p messages, bypassing the ejection isolation. [9](#0-8) [10](#0-9)

### Citations

**File:** network/p2p/cache/protocol_state_provider.go (L19-28)
```go
// ProtocolStateIDCache implements an `id.IdentityProvider` and `p2p.IDTranslator` for the set of
// authorized Flow network participants as according to the given `protocol.State`.
// the implementation assumes that the node information changes rarely, while queries are frequent.
// Hence, we follow an event-driven design, where the ProtocolStateIDCache subscribes to relevant
// protocol notifications (mainly Epoch notifications) and updates its internally cached list of
// authorized node identities.
// Note: this implementation is _eventually consistent_, where changes in the protocol state will
// quickly, but not atomically, propagate to the ProtocolStateIDCache. This strongly benefits
// performance and modularity, as we can cache identities locally here, while the marginal
// delay of updates is of no concern to the protocol.
```

**File:** network/p2p/cache/protocol_state_provider.go (L65-96)
```go
// EpochTransition is a callback function for notifying the `ProtocolStateIDCache`
// of an Epoch transition that just occurred. Upon such notification, the internally-cached
// Identity table of authorized network participants is updated.
//
// TODO(EFM, #6123): per API contract, implementations of `EpochTransition` should be non-blocking
// and virtually latency free. However, we run data base queries and acquire locks here,
// which is undesired.
func (p *ProtocolStateIDCache) EpochTransition(newEpochCounter uint64, header *flow.Header) {
	p.update(header.ID())
}

// EpochSetupPhaseStarted is a callback function for notifying the `ProtocolStateIDCache`
// that the EpochSetup Phase has just stared. Upon such notification, the internally-cached
// Identity table of authorized network participants is updated.
//
// TODO(EFM, #6123): per API contract, implementations of `EpochSetupPhaseStarted` should be non-blocking
// and virtually latency free. However, we run data base queries and acquire locks here,
// which is undesired.
func (p *ProtocolStateIDCache) EpochSetupPhaseStarted(currentEpochCounter uint64, header *flow.Header) {
	p.update(header.ID())
}

// EpochCommittedPhaseStarted is a callback function for notifying the `ProtocolStateIDCache`
// that the EpochCommitted Phase has just stared. Upon such notification, the internally-cached
// Identity table of authorized network participants is updated.
//
// TODO(EFM, #6123): per API contract, implementations of `EpochCommittedPhaseStarted` should be non-blocking
// and virtually latency free. However, we run data base queries and acquire locks here,
// which is undesired.
func (p *ProtocolStateIDCache) EpochCommittedPhaseStarted(currentEpochCounter uint64, header *flow.Header) {
	p.update(header.ID())
}
```

**File:** network/p2p/cache/protocol_state_provider.go (L103-135)
```go
func (p *ProtocolStateIDCache) update(blockID flow.Identifier) {
	p.logger.Info().Str("blockID", blockID.String()).Msg("updating cached identities")

	identities, err := p.state.AtBlockID(blockID).Identities(filter.Any)
	if err != nil {
		// We don't want to continue with an expired identity list.
		p.logger.Fatal().Err(err).Msg("failed to fetch new identities")
	}

	nIds := identities.Count()
	peerIDs := make(map[flow.Identifier]peer.ID, nIds)
	flowIDs := make(map[peer.ID]flow.Identifier, nIds)

	for _, identity := range identities {
		p.logger.Debug().Interface("identity", identity).Msg("extracting peer ID from network key")

		pid, err := keyutils.PeerIDFromFlowPublicKey(identity.NetworkPubKey)
		if err != nil {
			p.logger.Err(err).Interface("identity", identity).Msg("failed to extract peer ID from network key")
			continue
		}

		flowIDs[pid] = identity.NodeID
		peerIDs[identity.NodeID] = pid
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.identities = identities
	p.flowIDs = flowIDs
	p.peerIDs = peerIDs
	p.lookup = identities.Lookup()
}
```

**File:** state/protocol/events/gadgets/identity_deltas.go (L8-37)
```go
// IdentityDeltas is a protocol events consumer that provides an interface to
// subscribe to callbacks any time an identity table change (or possible change)
// is finalized.
//
// TODO(EFM, #6123) add slashing/ejection events here once implemented
// TODO(EFM, #6123): Consider consolidating this with ProtocolStateIDCache
type IdentityDeltas struct {
	events.Noop
	callback func()
}

// NewIdentityDeltas returns a new IdentityDeltas events gadget.
func NewIdentityDeltas(cb func()) *IdentityDeltas {
	deltas := &IdentityDeltas{
		callback: cb,
	}
	return deltas
}

func (g *IdentityDeltas) EpochTransition(_ uint64, _ *flow.Header) {
	g.callback()
}

func (g *IdentityDeltas) EpochSetupPhaseStarted(_ uint64, _ *flow.Header) {
	g.callback()
}

func (g *IdentityDeltas) EpochCommittedPhaseStarted(_ uint64, _ *flow.Header) {
	g.callback()
}
```

**File:** state/protocol/protocol_state/epochs/identity_ejector.go (L44-61)
```go
func (e *ejector) Eject(nodeID flow.Identifier) bool {
	l := len(e.identityLists)
	if len(e.ejected) == 0 { // if this is the first ejection sealed in this block, we have to populate the lookup first
		for i := range l {
			e.identityLists[i].identityLookup = e.identityLists[i].dynamicIdentities.Lookup()
		}
	}
	e.ejected = append(e.ejected, nodeID)

	var nodeFound bool
	for i := range l {
		dynamicIdentity, found := e.identityLists[i].identityLookup[nodeID]
		if found {
			nodeFound = true
			dynamicIdentity.Ejected = true
		}
	}
	return nodeFound
```

**File:** network/p2p/builder/utils.go (L19-28)
```go
func notEjectedPeerFilter(idProvider module.IdentityProvider) p2p.PeerFilter {
	return func(p peer.ID) error {
		if id, found := idProvider.ByPeerID(p); !found {
			return fmt.Errorf("failed to get identity of unknown peer with peer id %s", p2plogging.PeerId(p))
		} else if id.IsEjected() {
			return fmt.Errorf("peer %s with node id %s is ejected", p2plogging.PeerId(p), id.NodeID.String())
		}

		return nil
	}
```

**File:** network/p2p/builder/libp2pNodeBuilder.go (L455-463)
```go
	// set the default connection gater peer filters for both InterceptPeerDial and InterceptSecured callbacks
	peerFilter := notEjectedPeerFilter(idProvider)
	peerFilters := []p2p.PeerFilter{peerFilter}

	connGater := connection.NewConnGater(
		logger,
		idProvider,
		connection.WithOnInterceptPeerDialFilters(append(peerFilters, connGaterCfg.InterceptPeerDialFilters...)),
		connection.WithOnInterceptSecuredFilters(append(peerFilters, connGaterCfg.InterceptSecuredFilters...)))
```

**File:** network/p2p/scoring/utils.go (L11-21)
```go
func HasValidFlowIdentity(idProvider module.IdentityProvider, pid peer.ID) (*flow.Identity, error) {
	flowId, ok := idProvider.ByPeerID(pid)
	if !ok {
		return nil, NewInvalidPeerIDError(pid, PeerIdStatusUnknown)
	}

	if flowId.IsEjected() {
		return nil, NewInvalidPeerIDError(pid, PeerIdStatusEjected)
	}

	return flowId, nil
```

**File:** network/p2p/connection/connection_gater.go (L74-113)
```go
func (c *ConnGater) InterceptPeerDial(p peer.ID) bool {
	lg := c.log.With().Str("peer_id", p2plogging.PeerId(p)).Logger()

	disallowListCauses, disallowListed := c.disallowListOracle.IsDisallowListed(p)
	if disallowListed {
		lg.Warn().
			Str("disallow_list_causes", fmt.Sprintf("%v", disallowListCauses)).
			Msg("outbound connection attempt to disallow listed peer is rejected")
		return false
	}

	if len(c.onInterceptPeerDialFilters) == 0 {
		lg.Warn().
			Msg("outbound connection established with no intercept peer dial filters")
		return true
	}

	identity, ok := c.identityProvider.ByPeerID(p)
	if !ok {
		lg = lg.With().
			Str("remote_node_id", "unknown").
			Str("role", "unknown").
			Logger()
	} else {
		lg = lg.With().
			Hex("remote_node_id", logging.ID(identity.NodeID)).
			Str("role", identity.Role.String()).
			Logger()
	}

	if err := c.peerIDPassesAllFilters(p, c.onInterceptPeerDialFilters); err != nil {
		// log the filtered outbound connection attempt
		lg.Warn().
			Err(err).
			Msg("rejected outbound connection attempt")
		return false
	}

	lg.Debug().Msg("outbound connection established")
	return true
```
