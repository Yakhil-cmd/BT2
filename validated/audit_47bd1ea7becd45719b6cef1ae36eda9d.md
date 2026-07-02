### Title
`ProtocolStateIDCache` Does Not Subscribe to `EjectNode` Service Events — Ejected Node Remains Authorized on the Network Layer - (File: `network/p2p/cache/protocol_state_provider.go`)

---

### Summary

`ProtocolStateIDCache` is the sole identity provider used by the networking layer to authorize incoming unicast streams and GossipSub messages. It updates its cached identity table only on epoch-phase transitions (`EpochTransition`, `EpochSetupPhaseStarted`, `EpochCommittedPhaseStarted`). It has no callback for mid-epoch `EjectNode` service events. As a result, a node that is ejected mid-epoch continues to be treated as an authorized, non-ejected peer by the networking layer until the next epoch-phase event fires — which may be many blocks later or never (in Epoch Fallback Mode). This is the direct analog of the `phenomanelTree.sol` bug: a mutable role/status is assumed to be fixed, and the component that checks it reads a stale cached value.

---

### Finding Description

`ProtocolStateIDCache` embeds `events.Noop`, which provides no-op implementations for all protocol consumer callbacks. [1](#0-0) 

It overrides only three callbacks — `EpochTransition`, `EpochSetupPhaseStarted`, and `EpochCommittedPhaseStarted` — each of which calls `p.update(header.ID())` to refresh the cached identity list. [2](#0-1) 

There is no override for an `EjectNode` notification. The `protocol.Consumer` interface (via `events.Noop`) silently absorbs any such notification without refreshing the cache.

The `update` function reads the full identity list from the protocol state at a given block, including the `Ejected` flag on each identity. [3](#0-2) 

The networking layer uses `ProtocolStateIDCache` (wrapped in `NodeDisallowListWrapper`) as the `IdentityProvider` for:

1. **Unicast stream authorization** — `getAuthorizedIdentity` calls `n.Identity(remotePeer)` which resolves through `ByPeerID`, then checks `remoteIdentity.IsEjected()`. [4](#0-3) 

2. **GossipSub RPC inspection** — `checkSenderIdentity` calls `c.idProvider.ByPeerID(pid)` then checks `id.IsEjected()`. [5](#0-4) 

3. **PubSub topic validator** — `isProtocolParticipant` calls `ByPeerID` and checks the ejection flag. [6](#0-5) 

Because the cache is not refreshed when an `EjectNode` service event is sealed, the `Ejected` flag in the cached identity remains `false` for the ejected node. All three authorization paths therefore continue to pass the ejected node as authorized.

The `EjectNode` service event is a first-class protocol event that updates the Dynamic Protocol State mid-epoch. [7](#0-6) 

The `EpochStateMachine` processes it immediately when a block sealing it is finalized. [8](#0-7) 

But the `ProtocolStateIDCache` has no corresponding notification hook, so the networking layer's view of the identity table diverges from the protocol state.

---

### Impact Explanation

An ejected node — one whose keys may be compromised or which has committed a protocol violation — retains full network-layer authorization on every peer that has not yet received an epoch-phase event. Concretely:

- The ejected node can open unicast streams to any staked node and have its messages processed (not dropped at the stream-open check).
- The ejected node can publish GossipSub messages on private channels (e.g., `ConsensusCommittee`, `RequestCollections`) and pass the `AuthorizedSenderValidator` check, because `isAuthorizedSender` reads the stale `Ejected=false` flag.
- The ejected node can send block proposals, execution receipts, result approvals, or collection requests that will be forwarded to engine handlers, bypassing the first line of network-layer defense.

In Epoch Fallback Mode (EFM), no epoch-phase events fire at all, so the window is unbounded — an ejected node remains authorized for the entire duration of EFM.

---

### Likelihood Explanation

The `EjectNode` service event is a live, on-chain mechanism used in production (e.g., self-ejection when keys are suspected compromised, or governance-triggered ejection for protocol violations). The gap between the service event being sealed and the next epoch-phase event can span many blocks. In EFM the gap is indefinite. Any ejected node operator who retains their networking key can exploit this window immediately after ejection is sealed, without any additional privileges.

---

### Recommendation

Add a `NodeEjected` (or equivalent block-finalization) callback to `ProtocolStateIDCache` that triggers `p.update(header.ID())` whenever a block sealing an `EjectNode` event is finalized. The `protocol.Consumer` interface or a dedicated `EjectNode` consumer interface should be extended to deliver this notification. Alternatively, subscribe to every block finalization and refresh the cache, accepting the performance trade-off. The `NodeDisallowListWrapper` pattern (which already overrides the `Ejected` flag via an admin command) demonstrates that the architecture supports this kind of override. [9](#0-8) 

---

### Proof of Concept

**Step 1 — Ejection is sealed on-chain.**
A governance transaction emits an `EjectNode` service event for node `X`. The `EpochStateMachine` processes it when the sealing block is finalized, setting `X.Ejected = true` in the protocol state. [10](#0-9) 

**Step 2 — `ProtocolStateIDCache` is not notified.**
No epoch-phase event fires. `ProtocolStateIDCache.update()` is never called. The cached `lookup` map still holds `X` with `Ejected = false`. [2](#0-1) 

**Step 3 — Node X opens a unicast stream.**
`Network.handleIncomingStream` calls `getAuthorizedIdentity`, which calls `n.Identity(remotePeer)` → `ByPeerID` → returns the stale cached identity with `Ejected = false`. The `IsEjected()` check passes. The stream is accepted. [4](#0-3) 

**Step 4 — Node X publishes on a private GossipSub channel.**
`AuthorizedSenderValidator.isAuthorizedSender` reads `identity.IsEjected()` from the same stale cache — returns `false` — and proceeds to role/channel authorization. Since `X`'s role is still valid in the cache, the message passes. [11](#0-10) 

**Step 5 — In EFM, this window is indefinite.**
`ProtocolStateIDCache` only refreshes on `EpochTransition`, `EpochSetupPhaseStarted`, and `EpochCommittedPhaseStarted`. In EFM none of these fire, so `X` remains authorized on the network layer for the entire fallback period. [2](#0-1)

### Citations

**File:** network/p2p/cache/protocol_state_provider.go (L19-38)
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

**File:** network/underlay/network.go (L1156-1167)
```go
	if channels.IsPublicChannel(channel) {
		// NOTE: for public channels the callback used to check if a node is staked will
		// return true for every node.
		peerFilter = p2p.AllowAllPeerFilter()
	} else {
		// for channels used by the staked nodes, add the topic validator to filter out messages from non-staked nodes
		validators = append(validators, n.authorizedSenderValidator.PubSubMessageValidator(channel))

		// NOTE: For non-public channels the libP2P node topic validator will reject
		// messages from unstaked nodes.
		peerFilter = n.isProtocolParticipant()
	}
```

**File:** network/p2p/inspector/validation/control_message_validation_inspector.go (L341-351)
```go
func (c *ControlMsgValidationInspector) checkSenderIdentity(pid peer.ID) (*flow.Identity, error) {
	id, ok := c.idProvider.ByPeerID(pid)
	if !ok {
		return nil, NewUnstakedPeerErr(pid)
	}

	if id.IsEjected() {
		return nil, NewEjectedPeerErr(pid)
	}

	return id, nil
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

**File:** state/protocol/protocol_state/epochs/statemachine.go (L368-373)
```go
		case *flow.EjectNode:
			_ = e.activeStateMachine.EjectIdentity(ev)
		default:
			continue
		}
	}
```

**File:** state/protocol/protocol_state/epochs/base_statemachine.go (L79-89)
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
}
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
