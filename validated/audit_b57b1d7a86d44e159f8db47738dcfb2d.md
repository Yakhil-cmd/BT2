### Title
`ProtocolStateIDCache` Not Updated on `EpochFallbackModeTriggered` / `EpochFallbackModeExited` — (`File: network/p2p/cache/protocol_state_provider.go`)

---

### Summary

`ProtocolStateIDCache` maintains a cached list of authorized network participants and refreshes it only on three epoch-phase events: `EpochTransition`, `EpochSetupPhaseStarted`, and `EpochCommittedPhaseStarted`. It does **not** refresh on `EpochFallbackModeTriggered`, `EpochFallbackModeExited`, or `EpochExtended`. During Epoch Fallback Mode (EFM), node ejections (`EjectNode` service events) can be sealed and finalized, changing the protocol-state identity table, while none of the three cache-refreshing events fire. The cache therefore remains stale for the entire duration of EFM, and ejected nodes continue to appear as non-ejected, allowing them to maintain authorized P2P connections and deliver messages to every engine on every node.

---

### Finding Description

`ProtocolStateIDCache` embeds `events.Noop`, which provides no-op implementations for all `protocol.Consumer` callbacks. The struct overrides only three of those callbacks:

```go
func (p *ProtocolStateIDCache) EpochTransition(...)          { p.update(header.ID()) }
func (p *ProtocolStateIDCache) EpochSetupPhaseStarted(...)   { p.update(header.ID()) }
func (p *ProtocolStateIDCache) EpochCommittedPhaseStarted(...){ p.update(header.ID()) }
``` [1](#0-0) 

The remaining callbacks — `EpochFallbackModeTriggered`, `EpochFallbackModeExited`, `EpochExtended` — are inherited as no-ops from `events.Noop`: [2](#0-1) 

The protocol state emits `EpochFallbackModeTriggered` when EFM begins, and `EpochFallbackModeExited` when an `EpochRecover` event is processed. Both events are distributed to all registered consumers via `events.Distributor`: [3](#0-2) 

During EFM, the `FallbackStateMachine` continues to process `EjectNode` service events, updating `ActiveIdentities` in the protocol state: [4](#0-3) 

The ejection is committed to the protocol state and finalized. `epochMetricsAndEventsOnBlockFinalized` fires `EpochFallbackModeTriggered` but **no** `EpochTransition`, `EpochSetupPhaseStarted`, or `EpochCommittedPhaseStarted`: [5](#0-4) 

Because none of the three cache-refreshing events fire during EFM, `ProtocolStateIDCache.update()` is never called, and the cached identity list retains the pre-ejection state for the entire duration of EFM.

`ProtocolStateIDCache` is instantiated as the `IdentityProvider` for every node type: [6](#0-5) [7](#0-6) 

The `SyncEngineIdentifierProvider` applies `filter.NotEjectedFilter` against this provider: [8](#0-7) 

Because the stale cache still marks the ejected node as `Ejected = false`, `filter.NotEjectedFilter` passes the ejected node through. The networking layer continues to accept connections from it and route its messages to all engines.

---

### Impact Explanation

An ejected node — one that the protocol has explicitly removed for misbehavior — can continue to maintain authorized LibP2P connections and deliver messages to every engine (consensus ingestion, verification, sealing, sync) on every peer for the entire duration of EFM. This defeats the ejection security mechanism: the ejected node can continue sending invalid votes, result approvals, or spam that consumes resources on all peers. If the ejected node is a malicious Access Node, it can continue serving API responses to clients with stale or manipulated data.

---

### Likelihood Explanation

EFM is a realistic, protocol-defined state that can be triggered by a single invalid service event or by the epoch commitment deadline passing without a valid `EpochCommit`. Once in EFM, the protocol can remain there for an extended period (multiple epoch extensions) until a valid `EpochRecover` event is processed. During that window, any `EjectNode` service event sealed and finalized leaves the cache permanently stale until EFM exits. The attacker-controlled entry path is: the ejected node simply continues operating after its ejection is finalized, exploiting the stale cache to maintain network access.

---

### Recommendation

Add handlers for `EpochFallbackModeTriggered`, `EpochFallbackModeExited`, and `EpochExtended` in `ProtocolStateIDCache` that call `p.update(header.ID())`, mirroring the existing handlers for the three epoch-phase events. This ensures the cached identity list is refreshed whenever the protocol state's identity table changes, regardless of which event triggered the change.

---

### Proof of Concept

1. EFM is triggered (e.g., invalid `EpochSetup` service event is sealed and finalized).
2. `FollowerState.Finalize` calls `epochMetricsAndEventsOnBlockFinalized`, which emits `EpochFallbackModeTriggered` — `ProtocolStateIDCache` receives a no-op.
3. A subsequent `EjectNode` service event for a malicious consensus node is sealed and finalized; `FallbackStateMachine.EjectIdentity` sets `Ejected = true` in the protocol state's `ActiveIdentities`.
4. No `EpochTransition`, `EpochSetupPhaseStarted`, or `EpochCommittedPhaseStarted` fires (EFM suppresses normal phase transitions).
5. `ProtocolStateIDCache.update()` is never called; the cached identity list still shows the ejected node with `Ejected = false`.
6. `filter.NotEjectedFilter` passes the ejected node; the networking layer accepts its connections and routes its messages to all engines.
7. The ejected malicious node continues to participate in the network until EFM exits and a cache-refreshing event fires.

### Citations

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

**File:** state/protocol/events/noop.go (L27-31)
```go
func (n Noop) EpochFallbackModeTriggered(uint64, *flow.Header) {}

func (n Noop) EpochFallbackModeExited(uint64, *flow.Header) {}

func (n Noop) EpochExtended(uint64, *flow.Header, flow.EpochExtension) {}
```

**File:** state/protocol/events/distributor.go (L70-92)
```go
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

**File:** state/protocol/protocol_state/epochs/fallback_statemachine.go (L11-19)
```go
// FallbackStateMachine is a special structure that encapsulates logic for processing service events
// when protocol is in epoch fallback mode. The FallbackStateMachine ignores EpochSetup and EpochCommit
// events but still processes ejection events.
//
// Whenever invalid epoch state transition has been observed only epochFallbackStateMachines must be created for subsequent views.
type FallbackStateMachine struct {
	baseStateMachine
	parentState protocol.KVStoreReader
}
```

**File:** state/protocol/badger/mutator.go (L947-961)
```go
	// Check for entering or exiting EFM
	if !parentEpochState.EpochFallbackTriggered() && finalizedEpochState.EpochFallbackTriggered() {
		// this block triggers EFM
		events = append(events, func() {
			m.consumer.EpochFallbackModeTriggered(childEpochCounter, finalized)
		})
		metrics = append(metrics, m.metrics.EpochFallbackModeTriggered)
	}
	if parentEpochState.EpochFallbackTriggered() && !finalizedEpochState.EpochFallbackTriggered() {
		// this block exits EFM
		events = append(events, func() {
			m.consumer.EpochFallbackModeExited(childEpochCounter, finalized)
		})
		metrics = append(metrics, m.metrics.EpochFallbackModeExited)
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

**File:** cmd/scaffold.go (L1296-1303)
```go
		node.SyncEngineIdentifierProvider = id.NewIdentityFilterIdentifierProvider(
			filter.And(
				filter.HasRole[flow.Identity](flow.RoleConsensus),
				filter.Not(filter.HasNodeID[flow.Identity](node.Me.NodeID())),
				filter.NotEjectedFilter,
			),
			node.IdentityProvider,
		)
```

**File:** cmd/observer/node_builder/observer_builder.go (L999-1016)
```go
func (builder *ObserverServiceBuilder) InitIDProviders() {
	builder.Module("id providers", func(node *cmd.NodeConfig) error {
		idCache, err := cache.NewProtocolStateIDCache(node.Logger, node.State, builder.ProtocolEvents)
		if err != nil {
			return fmt.Errorf("could not initialize ProtocolStateIDCache: %w", err)
		}
		builder.IDTranslator = translator.NewHierarchicalIDTranslator(idCache, translator.NewPublicNetworkIDTranslator())

		// The following wrapper allows to black-list byzantine nodes via an admin command:
		// the wrapper overrides the 'Ejected' flag of disallow-listed nodes to true
		builder.IdentityProvider, err = cache.NewNodeDisallowListWrapper(
			idCache,
			node.ProtocolDB,
			func() network.DisallowListNotificationConsumer {
				return builder.NetworkUnderlay
			},
		)
		if err != nil {
```
