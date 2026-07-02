### Title
`ProtocolStateIDCache` Does Not Update on Mid-Epoch Node Ejection, Allowing Ejected Nodes to Bypass Authorization Checks — (`network/p2p/cache/protocol_state_provider.go`)

### Summary

`ProtocolStateIDCache` is the identity provider used by all network-layer authorization checks. It updates its cached identity table only on epoch phase-transition events (`EpochTransition`, `EpochSetupPhaseStarted`, `EpochCommittedPhaseStarted`). However, the Flow protocol supports mid-epoch node ejection via the `EjectNode` service event. When a node is ejected mid-epoch, the protocol state is updated immediately, but `ProtocolStateIDCache` has no subscription to any ejection notification and therefore continues to serve the ejected node's identity with `EpochParticipationStatusActive`. Every downstream authorization check that relies on this cache — including `AuthorizedSenderValidator.isAuthorizedSender()` and `Network.getAuthorizedIdentity()` — will continue to treat the ejected node as a valid, active participant until the next epoch phase transition, which may be weeks away.

### Finding Description

**Root cause — missing update trigger in `ProtocolStateIDCache`:**

`ProtocolStateIDCache` subscribes to the `protocol.Consumer` interface and implements only three update callbacks: [1](#0-0) 

None of these callbacks fire when a `ServiceEventEjectNode` is sealed. The `protocol.Consumer` interface itself has no "node ejected" event: [2](#0-1) 

The `EjectNode` service event type exists and is processed by the protocol state machine: [3](#0-2) 

When sealed, it causes the protocol state to mark the node's `DynamicIdentityEntry.Ejected = true`: [4](#0-3) 

But `ProtocolStateIDCache.update()` is never called in response. The cache's `lookup` map continues to hold the pre-ejection identity with `EpochParticipationStatusActive`: [5](#0-4) 

**Downstream authorization checks that fail:**

`AuthorizedSenderValidator.isAuthorizedSender()` calls `identity.IsEjected()` on the identity returned by the (stale) cache: [6](#0-5) 

`Network.getAuthorizedIdentity()` similarly calls `remoteIdentity.IsEjected()` on the cached value: [7](#0-6) 

`notEjectedPeerFilter` used in GossipSub peer filtering also relies on the same provider: [8](#0-7) 

All three checks return "not ejected" for the window between the `EjectNode` service event being sealed and the next epoch phase transition.

**The `NodeDisallowListWrapper` does not close this gap.** It provides an admin-level override but does not subscribe to protocol-level `EjectNode` events either: [9](#0-8) 

**Analog to reNFT M-10:** In reNFT, `Guard.sol` does not check whether it is still active in `Kernel.sol`, so a deactivated guard continues to enforce stale security policies. Here, `ProtocolStateIDCache` does not subscribe to `EjectNode` notifications, so a deactivated (ejected) node continues to pass all network-layer authorization checks.

### Impact Explanation

An ejected node — ejected precisely because it was behaving maliciously or its keys were compromised — can continue to:

- Send execution receipts on `PushReceipts` (private channel, Execution role) that pass `AuthorizedSenderValidator`
- Send result approvals on `PushApprovals` (Verification role)
- Participate in consensus gossip on `ConsensusCommittee`
- Establish unicast streams that pass `getAuthorizedIdentity`

The window lasts from the block that seals the `EjectNode` event until the next epoch phase transition (`EpochSetupPhaseStarted`, `EpochCommittedPhaseStarted`, or `EpochTransition`). In the staking phase of a long epoch this window can span weeks. This allows a Byzantine node to continue influencing protocol-critical pipelines (execution result acceptance, verification, consensus) after the network has formally ejected it, undermining the security guarantee that ejection is supposed to provide.

### Likelihood Explanation

The `EjectNode` service event is a live, production-deployed feature. Any node ejected mid-epoch (e.g., for double-signing or key compromise) triggers this exact condition automatically. The ejected node operator retains their private keys and can continue running their node software. No special attacker capability beyond possessing the ejected node's networking key is required.

### Recommendation

Add a `NodeEjected(nodeID flow.Identifier, header *flow.Header)` callback to the `protocol.Consumer` interface and emit it from `FollowerState.epochMetricsAndEventsOnBlockFinalized` whenever an `EjectNode` service event is sealed. `ProtocolStateIDCache` should implement this callback and call `p.update(header.ID())` in response, mirroring the pattern already used for epoch phase transitions: [10](#0-9) 

Alternatively, `ProtocolStateIDCache` can be changed to update on every block finalization rather than only on epoch events, accepting the performance trade-off.

### Proof of Concept

1. Node X (e.g., an Execution node) is ejected mid-epoch: the Flow smart contract emits `EjectNode{NodeID: X}`. This is sealed in block B.
2. `FollowerState` finalizes block B and updates the protocol state: `X.Ejected = true` in `DynamicIdentityEntry`.
3. No epoch phase transition occurs (B is in the staking phase of a long epoch).
4. `ProtocolStateIDCache` is never notified; its `lookup` map still holds `X`'s identity with `EpochParticipationStatusActive`.
5. Node X sends an `ExecutionReceipt` message on the `PushReceipts` channel.
6. `AuthorizedSenderValidator.Validate()` calls `idProvider.ByPeerID(X.peerID)` → returns stale identity with `IsEjected() == false`.
7. `isAuthorizedSender()` passes the ejection check at line 125 and the role/channel check.
8. The receipt is accepted and forwarded to the consensus pipeline, despite X being formally ejected. [11](#0-10) [12](#0-11) [13](#0-12)

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

**File:** network/p2p/cache/protocol_state_provider.go (L103-134)
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
```

**File:** state/protocol/events/noop.go (L1-30)
```go
package events

import (
	"github.com/onflow/flow-go/model/flow"
	"github.com/onflow/flow-go/state/protocol"
)

// Noop is a no-op implementation of protocol.Consumer.
type Noop struct{}

var _ protocol.Consumer = (*Noop)(nil)

func NewNoop() *Noop {
	return &Noop{}
}

func (n Noop) BlockFinalized(*flow.Header) {}

func (n Noop) BlockProcessable(*flow.Header, *flow.QuorumCertificate) {}

func (n Noop) EpochTransition(uint64, *flow.Header) {}

func (n Noop) EpochSetupPhaseStarted(uint64, *flow.Header) {}

func (n Noop) EpochCommittedPhaseStarted(uint64, *flow.Header) {}

func (n Noop) EpochFallbackModeTriggered(uint64, *flow.Header) {}

func (n Noop) EpochFallbackModeExited(uint64, *flow.Header) {}

```

**File:** model/flow/service_event.go (L28-28)
```go
	ServiceEventEjectNode                   ServiceEventType = "eject-node"                     // Marks node with specified NodeID as 'ejected' in the protocol state
```

**File:** state/protocol/protocol_state/epochs/base_statemachine.go (L79-88)
```go
func (u *baseStateMachine) EjectIdentity(ejectionEvent *flow.EjectNode) bool {
	u.telemetry.OnServiceEventReceived(ejectionEvent.ServiceEvent())
	wasEjected := u.ejector.Eject(ejectionEvent.NodeID)
	if wasEjected {
		u.telemetry.OnServiceEventProcessed(ejectionEvent.ServiceEvent())
	} else {
		u.telemetry.OnInvalidServiceEvent(ejectionEvent.ServiceEvent(),
			protocol.NewInvalidServiceEventErrorf("could not eject node with unknown NodeID %v", ejectionEvent.NodeID))
	}
	return wasEjected
```

**File:** network/validator/authorized_sender_validator.go (L124-151)
```go
func (av *AuthorizedSenderValidator) isAuthorizedSender(identity *flow.Identity, channel channels.Channel, msgCode codec.MessageCode, protocol message.ProtocolType) (string, error) {
	if identity.IsEjected() {
		return "", ErrSenderEjected
	}

	// attempt to get the message interface from the message code encoded into the first byte of the message payload
	// this will be used to get the message auth configuration.
	msgInterface, what, err := codec.InterfaceFromMessageCode(msgCode)
	if err != nil {
		return "", fmt.Errorf("could not extract interface from message code %v: %w", msgCode, err)
	}

	// get message auth config
	conf, err := message.GetMessageAuthConfig(msgInterface)
	if err != nil {
		return "", fmt.Errorf("could not get authorization config for interface %T: %w", msgInterface, err)
	}

	// handle special case for cluster prefixed channels
	if prefix, ok := channels.ClusterChannelPrefix(channel); ok {
		channel = channels.Channel(prefix)
	}

	if err := conf.EnsureAuthorized(identity.Role, channel, protocol); err != nil {
		return what, err
	}

	return what, nil
```

**File:** network/underlay/network.go (L1118-1146)
```go
func (n *Network) getAuthorizedIdentity(log zerolog.Logger, remotePeer peer.ID) (*flow.Identity, bool) {
	remoteIdentity, ok := n.Identity(remotePeer)
	if !ok {
		log.Error().
			Str("remote_peer", remotePeer.String()).
			Bool(logging.KeySuspicious, true).
			Msg("failed to resolve identity of remote peer")
		n.slashingViolationsConsumer.OnUnauthorizedSenderError(&network.Violation{
			PeerID:   p2plogging.PeerId(remotePeer),
			Protocol: message.ProtocolTypeUnicast,
			Err:      validator.ErrIdentityUnverified,
		})
		return nil, false
	}
	if remoteIdentity.IsEjected() {
		log.Error().
			Str("remote_peer", remotePeer.String()).
			Bool(logging.KeySuspicious, true).
			Msg("remote peer is ejected")
		n.slashingViolationsConsumer.OnSenderEjectedError(&network.Violation{
			OriginID: remoteIdentity.NodeID,
			Identity: remoteIdentity,
			PeerID:   p2plogging.PeerId(remotePeer),
			Protocol: message.ProtocolTypeUnicast,
			Err:      validator.ErrSenderEjected,
		})
		return nil, false
	}
	return remoteIdentity, true
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

**File:** network/p2p/cache/node_disallow_list_wrapper.go (L25-30)
```go
// NodeDisallowListWrapper is a wrapper for an `module.IdentityProvider` instance, where the
// wrapper overrides the `Ejected` flag to true for all NodeIDs in a `disallowList`.
// To avoid modifying the source of the identities, the wrapper creates shallow copies
// of the identities (whenever necessary) and modifies the `Ejected` flag only in
// the copy.
// The `NodeDisallowListWrapper` internally represents the `disallowList` as a map, to enable
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
