### Title
`ProtocolStateIDCache` Not Updated on `EjectNode` Service Event, Allowing Ejected Nodes to Bypass Networking Identity Validation - (File: network/p2p/cache/protocol_state_provider.go)

### Summary

`ProtocolStateIDCache` caches the network identity list and only refreshes it on epoch-phase protocol events. When a node is ejected mid-epoch via the `EjectNode` service event, the Dynamic Protocol State is updated immediately, but `ProtocolStateIDCache` retains the stale, pre-ejection identity snapshot. The ejected node's `Ejected` flag remains `false` in the cache for the remainder of the epoch, allowing it to pass networking-layer identity filters that rely on this cache.

### Finding Description

`ProtocolStateIDCache` implements `module.IdentityProvider` and `p2p.IDTranslator` for all node roles (Access, Consensus, Execution, Verification, Follower, Observer). It is populated at construction time and refreshed only when one of three epoch callbacks fires: [1](#0-0) 

The three callbacks are `EpochTransition`, `EpochSetupPhaseStarted`, and `EpochCommittedPhaseStarted`. The struct embeds `events.Noop`, so every other `protocol.Consumer` method — including any future ejection notification — is a no-op. [2](#0-1) 

The Flow protocol exposes a `EjectNode` service event that the Dynamic Protocol State processes via `EpochStateMachine.evolveActiveStateMachine`: [3](#0-2) 

This correctly marks the node as ejected in the on-chain protocol state. However, the `protocol.Consumer` interface — and therefore the `events.Distributor` — has no `EjectNode` callback: [4](#0-3) 

Because no epoch-phase event is emitted when a node is ejected mid-epoch, `ProtocolStateIDCache.update()` is never called, and the cached identity list continues to show the ejected node with `Ejected = false` until the next epoch phase transition.

### Impact Explanation

`ProtocolStateIDCache` is the `IdentityProvider` wired into the networking message validators on every node type: [5](#0-4) 

The validator `filter.IsValidCurrentEpochParticipant` and `filter.NotEjectedFilter` both read the `Ejected` flag from the identity returned by the cache. Because the cache is stale, the ejected node's identity still passes these filters. Concretely:

- The ejected node can continue to send messages to Access nodes and have them accepted at the networking layer.
- The ejected node remains in the `SyncEngineParticipantsProviderFactory` participant list, so other nodes may attempt to sync with it.
- The desync persists for the remainder of the epoch (epochs span ~500 k views), which is a very long window.

The `NodeDisallowListWrapper` provides a manual operator workaround, but it requires an out-of-band admin command and is not triggered automatically by the `EjectNode` service event. [6](#0-5) 

### Likelihood Explanation

The `EjectNode` service event is a live governance mechanism already wired into the state machine. Any governance transaction that emits `EjectNode` mid-epoch (i.e., not coinciding with an epoch phase transition) will leave `ProtocolStateIDCache` stale. The ejected node itself is the attacker: it can immediately exploit the window by continuing to send messages that pass identity validation. No privileged key or quorum compromise is required beyond the governance action that triggered the ejection.

### Recommendation

1. **Add a `NodeEjected` callback to `protocol.Consumer`** and emit it from `FollowerState.Finalize` whenever an `EjectNode` service event is sealed. `ProtocolStateIDCache` can then implement this callback to call `update()`.
2. **Alternatively**, have `ProtocolStateIDCache` also subscribe to `BlockFinalized` and refresh the cache on every finalization. This is heavier but eliminates the entire class of desync.
3. **Alternatively**, remove the local cache for the `Ejected` flag and always read it dynamically from `protocol.State` at query time, similar to the first mitigation suggested in the original M-01 report.

### Proof of Concept

1. Governance emits an `EjectNode` service event for node `N` in block `B` (mid-epoch, no epoch phase change).
2. `EpochStateMachine.evolveActiveStateMachine` processes the event and sets `N.Ejected = true` in the Dynamic Protocol State.
3. `FollowerState.Finalize` finalizes block `B`. No epoch-phase protocol event is emitted, so `ProtocolStateIDCache.update()` is never called.
4. `ProtocolStateIDCache` still holds the pre-ejection snapshot where `N.Ejected = false`.
5. Node `N` sends a message to an Access node. `publicNetworkMsgValidators` calls `filter.IsValidCurrentEpochParticipant` against the stale cache — the filter passes.
6. The message is accepted at the networking layer. This continues until the next epoch phase event (potentially hundreds of thousands of views later). [7](#0-6) [8](#0-7) [3](#0-2) [9](#0-8)

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

**File:** network/p2p/cache/protocol_state_provider.go (L44-63)
```go
func NewProtocolStateIDCache(
	logger zerolog.Logger,
	state protocol.State,
	eventDistributor *events.Distributor,
) (*ProtocolStateIDCache, error) {
	provider := &ProtocolStateIDCache{
		state:  state,
		logger: logger.With().Str("component", "protocol-state-id-cache").Logger(),
	}

	head, err := state.Final().Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest state header: %w", err)
	}

	provider.update(head.ID())
	eventDistributor.AddConsumer(provider)

	return provider, nil
}
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

**File:** network/p2p/cache/protocol_state_provider.go (L98-135)
```go
// update updates the cached identities stored in this provider.
// This is called whenever an epoch event occurs, signaling a possible change in
// protocol state identities.
// Caution: this function is non-negligible latency (data base reads and acquiring locks). Therefore,
// it is _not suitable_ to be executed by the publisher thread for protocol notifications.
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

**File:** state/protocol/protocol_state/epochs/statemachine.go (L368-372)
```go
		case *flow.EjectNode:
			_ = e.activeStateMachine.EjectIdentity(ev)
		default:
			continue
		}
```

**File:** state/protocol/events/distributor.go (L46-92)
```go
func (d *Distributor) EpochTransition(newEpoch uint64, first *flow.Header) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochTransition(newEpoch, first)
	}
}

func (d *Distributor) EpochSetupPhaseStarted(epoch uint64, first *flow.Header) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochSetupPhaseStarted(epoch, first)
	}
}

func (d *Distributor) EpochCommittedPhaseStarted(epoch uint64, first *flow.Header) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochCommittedPhaseStarted(epoch, first)
	}
}

func (d *Distributor) EpochFallbackModeTriggered(epochCounter uint64, header *flow.Header) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochFallbackModeTriggered(epochCounter, header)
	}
}

func (d *Distributor) EpochFallbackModeExited(epochCounter uint64, header *flow.Header) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochFallbackModeExited(epochCounter, header)
	}
}

func (d *Distributor) EpochExtended(epochCounter uint64, header *flow.Header, extension flow.EpochExtension) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, sub := range d.subscribers {
		sub.EpochExtended(epochCounter, header, extension)
	}
}
```

**File:** cmd/access/node_builder/access_node_builder.go (L1774-1787)
```go
func publicNetworkMsgValidators(log zerolog.Logger, idProvider module.IdentityProvider, selfID flow.Identifier) []network.MessageValidator {
	return []network.MessageValidator{
		// filter out messages sent by this node itself
		validator.ValidateNotSender(selfID),
		validator.NewAnyValidator(
			// message should be either from a valid staked node
			validator.NewOriginValidator(
				id.NewIdentityFilterIdentifierProvider(filter.IsValidCurrentEpochParticipant, idProvider),
			),
			// or the message should be specifically targeted for this node
			validator.ValidateTarget(log, selfID),
		),
	}
}
```

**File:** network/p2p/cache/node_disallow_list_wrapper.go (L107-113)
```go
}

// ClearDisallowList purges the set of blocked node IDs. Convenience function
// equivalent to w.Update(nil). No errors are expected during normal operations.
func (w *NodeDisallowListWrapper) ClearDisallowList() error {
	return w.Update(nil)
}
```

**File:** model/flow/epoch.go (L641-659)
```go
// EjectNode is a service event emitted when a node has to be ejected from the network.
// The Dynamic Protocol State observes these events and updates the identity table accordingly.
// It contains a single field which is the identifier of the node being ejected.
type EjectNode struct {
	NodeID Identifier
}

// EqualTo returns true if the two events are equivalent.
func (e *EjectNode) EqualTo(other *EjectNode) bool {
	return e.NodeID == other.NodeID
}

// ServiceEvent returns the event as a generic ServiceEvent type.
func (e *EjectNode) ServiceEvent() ServiceEvent {
	return ServiceEvent{
		Type:  ServiceEventEjectNode,
		Event: e,
	}
}
```
