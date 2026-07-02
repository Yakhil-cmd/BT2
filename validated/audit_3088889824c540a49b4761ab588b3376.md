### Title
Stale Identity Cache in `ProtocolStateIDCache` Due to Missing `EpochExtended` Handler — (File: `network/p2p/cache/protocol_state_provider.go`)

---

### Summary

`ProtocolStateIDCache` caches the authorized identity table for the Flow P2P networking layer. It subscribes to protocol events and refreshes its cache on epoch phase transitions. However, it does not handle the `EpochExtended` protocol event, which is the only epoch-related event emitted during Epoch Fallback Mode (EFM). As a result, during EFM, the cached identity table becomes permanently stale: nodes ejected via `EjectNode` service events are never reflected in the cache, allowing them to maintain unauthorized P2P network access.

---

### Finding Description

`ProtocolStateIDCache` embeds `events.Noop` and explicitly overrides only three protocol events to call its internal `update()` function:

- `EpochTransition`
- `EpochSetupPhaseStarted`
- `EpochCommittedPhaseStarted` [1](#0-0) [2](#0-1) 

The `update()` function re-fetches the full identity list from the protocol state and atomically replaces all five cached fields: `identities`, `peerIDs`, `flowIDs`, `lookup`, and the logger. [3](#0-2) 

The `protocol.Consumer` interface also defines `EpochExtended`, `EpochFallbackModeTriggered`, and `EpochFallbackModeExited`: [4](#0-3) 

These three events are left as no-ops via the embedded `events.Noop`: [5](#0-4) 

During EFM, the protocol state emits **only** `EpochFallbackModeTriggered`, `EpochExtended` (once per extension), and eventually `EpochFallbackModeExited`. None of the three events handled by `ProtocolStateIDCache` fire during EFM. The `EpochExtended` event is emitted by `FollowerState.epochMetricsAndEventsOnBlockFinalized` each time a new epoch extension is finalized: [6](#0-5) 

Because `ProtocolStateIDCache` does not override `EpochExtended`, the cache is never refreshed during EFM. Any `EjectNode` service event sealed during EFM updates the protocol state's `DynamicIdentity.Ejected` field, but this change is invisible to the cache until the next epoch transition — which may not occur for the entire duration of EFM (potentially spanning multiple epoch extensions).

---

### Impact Explanation

The `ProtocolStateIDCache` is the authoritative `IdentityProvider` and `IDTranslator` for the networking layer on all node types: [7](#0-6) 

The networking layer uses `filter.NotEjectedFilter` against identities returned by this cache to decide which peers are authorized. Because the stale cache still returns the ejected node's identity with `EpochParticipationStatus = Active`, the filter does not exclude it. The ejected node therefore:

1. Continues to have its libp2p peer ID recognized as a valid Flow node via `ByPeerID` / `GetFlowID`.
2. Maintains authorized P2P connections that should have been severed upon ejection.
3. Can continue sending and receiving protocol messages (gossip, sync, etc.) from other nodes that consult the same stale cache. [8](#0-7) 

The `NodeDisallowListWrapper` that wraps `ProtocolStateIDCache` only handles admin-level disallow-listing and does not compensate for missing ejection updates: [9](#0-8) 

---

### Likelihood Explanation

EFM is a designed, production-reachable protocol mechanism triggered automatically when an epoch commitment deadline is missed. Once EFM is active, `EjectNode` service events can be emitted by the smart contract to remove misbehaving nodes. The window of staleness lasts from the first `EpochExtended` event until the next `EpochTransition` — potentially spanning many epoch extensions (each adding `epochExtensionViewCount` views). This is not a marginal delay; it is a structural gap in the event subscription.

---

### Recommendation

**Short term:** Override `EpochExtended` (and `EpochFallbackModeTriggered` / `EpochFallbackModeExited`) in `ProtocolStateIDCache` to call `p.update(header.ID())`, mirroring the pattern already used for the three handled events.

**Long term:** Add a test that simulates an `EjectNode` service event sealed during EFM and verifies that `ProtocolStateIDCache` reflects the ejection after the subsequent `EpochExtended` notification is delivered.

---

### Proof of Concept

1. EFM is triggered (e.g., epoch commitment deadline missed). `EpochFallbackModeTriggered` fires — no-op in `ProtocolStateIDCache`.
2. A governance action emits an `EjectNode` service event for node `X`. The event is sealed in a block, updating `DynamicIdentity.Ejected = true` in the protocol state.
3. The epoch extension deadline is reached; `EpochExtended` fires — no-op in `ProtocolStateIDCache`.
4. Node `X` calls `ByPeerID` or `GetFlowID` on any peer's `ProtocolStateIDCache`. The cache still returns `X`'s identity with `EpochParticipationStatus = Active`.
5. The networking layer's `filter.NotEjectedFilter` passes node `X`, and its connections remain open.
6. Node `X` continues to send and receive P2P messages as if it were never ejected, until the next `EpochTransition` event (which may not occur for the entire remaining duration of EFM). [10](#0-9) [5](#0-4)

### Citations

**File:** network/p2p/cache/protocol_state_provider.go (L29-38)
```go
type ProtocolStateIDCache struct {
	events.Noop
	identities flow.IdentityList
	state      protocol.State
	mu         sync.RWMutex
	peerIDs    map[flow.Identifier]peer.ID
	flowIDs    map[peer.ID]flow.Identifier
	lookup     map[flow.Identifier]*flow.Identity
	logger     zerolog.Logger
}
```

**File:** network/p2p/cache/protocol_state_provider.go (L40-42)
```go
var _ module.IdentityProvider = (*ProtocolStateIDCache)(nil)
var _ protocol.Consumer = (*ProtocolStateIDCache)(nil)
var _ p2p.IDTranslator = (*ProtocolStateIDCache)(nil)
```

**File:** network/p2p/cache/protocol_state_provider.go (L72-96)
```go
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

**File:** network/p2p/cache/protocol_state_provider.go (L160-174)
```go
// ByPeerID returns the full identity for the node with the given peer ID,
// where ID is the way the libP2P refers to the node. The function
// has the same semantics as a map lookup, where the boolean return value is
// true if and only if Identity has been found, i.e. `Identity` is not nil.
// Caution: function returns include ejected nodes. Please check the `Ejected`
// flag in the identity.
func (p *ProtocolStateIDCache) ByPeerID(peerID peer.ID) (*flow.Identity, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if flowID, ok := p.flowIDs[peerID]; ok {
		id, ok := p.lookup[flowID]
		return id, ok
	}
	return nil, false
}
```

**File:** state/protocol/events.go (L112-119)
```go
	// EpochExtended is called when a flow.EpochExtension is added to the current epoch
	// Consumers can get context for handling events from:
	//   - epochCounter is the current epoch counter at the block when EFM was triggered
	//   - header is the block when EFM was triggered
	//
	// NOTE: This notification is emitted when the block triggering the EFM extension is finalized.
	EpochExtended(epochCounter uint64, header *flow.Header, extension flow.EpochExtension)
}
```

**File:** state/protocol/events/noop.go (L27-31)
```go
func (n Noop) EpochFallbackModeTriggered(uint64, *flow.Header) {}

func (n Noop) EpochFallbackModeExited(uint64, *flow.Header) {}

func (n Noop) EpochExtended(uint64, *flow.Header, flow.EpochExtension) {}
```

**File:** state/protocol/badger/mutator.go (L963-971)
```go
	// Check for a new epoch extension
	if len(finalizedEpochState.EpochExtensions()) > len(parentEpochState.EpochExtensions()) {
		// We expect at most one additional epoch extension per block, but tolerate more here
		for i := len(parentEpochState.EpochExtensions()); i < len(finalizedEpochState.EpochExtensions()); i++ {
			finalizedExtension := finalizedEpochState.EpochExtensions()[i]
			events = append(events, func() { m.consumer.EpochExtended(childEpochCounter, finalized, finalizedExtension) })
			metrics = append(metrics, func() { m.metrics.CurrentEpochFinalView(finalizedExtension.FinalView) })
		}
	}
```

**File:** cmd/scaffold.go (L1241-1260)
```go
func (fnb *FlowNodeBuilder) InitIDProviders() {
	fnb.Module("id providers", func(node *NodeConfig) error {
		idCache, err := cache.NewProtocolStateIDCache(node.Logger, node.State, node.ProtocolEvents)
		if err != nil {
			return fmt.Errorf("could not initialize ProtocolStateIDCache: %w", err)
		}

		// The following wrapper allows to disallow-list byzantine nodes via an admin command:
		// the wrapper overrides the 'Ejected' flag of disallow-listed nodes to true
		disallowListWrapper, err := cache.NewNodeDisallowListWrapper(
			idCache,
			node.ProtocolDB,
			func() network.DisallowListNotificationConsumer {
				return fnb.NetworkUnderlay
			},
		)
		if err != nil {
			return fmt.Errorf("could not initialize NodeDisallowListWrapper: %w", err)
		}
		node.IdentityProvider = disallowListWrapper
```

**File:** network/p2p/cache/node_disallow_list_wrapper.go (L172-191)
```go
func (w *NodeDisallowListWrapper) setEjectedIfBlocked(identity *flow.Identity) *flow.Identity {
	if identity == nil || identity.IsEjected() {
		return identity
	}

	w.m.RLock()
	isBlocked := w.disallowList.Contains(identity.NodeID)
	w.m.RUnlock()
	if !isBlocked {
		return identity
	}

	// For blocked nodes, we want to return their `Identity` with the `EpochParticipationStatus`
	// set to `flow.EpochParticipationStatusEjected`.
	// Caution: we need to copy the `Identity` before we override `EpochParticipationStatus`, as we
	// would otherwise potentially change the wrapped IdentityProvider.
	var i = *identity // shallow copy is sufficient, because `EpochParticipationStatus` is a value type in DynamicIdentity which is also a value type.
	i.EpochParticipationStatus = flow.EpochParticipationStatusEjected
	return &i
}
```
