### Title
Unauthenticated `TargetIDs` Field Bypasses Origin Identity Check on Public Network — (`network/validator/target_validator.go`, `cmd/access/node_builder/access_node_builder.go`, `follower/follower_builder.go`, `cmd/observer/node_builder/observer_builder.go`)

---

### Summary

The `publicNetworkMsgValidators` function used by Access Nodes, Observer nodes, and the Follower service constructs a logical OR validator that accepts a message if the sender is either a valid staked node **or** the message's `TargetIDs` field contains the receiving node's own ID. Because `TargetIDs` is a sender-controlled, unauthenticated field in the wire-level protobuf message, any unprivileged node on the public network can forge this field to bypass the staked-origin identity check entirely — injecting arbitrary protocol messages into the receiving node's engine pipeline.

---

### Finding Description

Three independent copies of `publicNetworkMsgValidators` are defined in:

- `cmd/access/node_builder/access_node_builder.go` lines 1774–1787
- `cmd/observer/node_builder/observer_builder.go` lines 956–969
- `follower/follower_builder.go` lines 368–381

All three are identical:

```go
func publicNetworkMsgValidators(...) []network.MessageValidator {
    return []network.MessageValidator{
        validator.ValidateNotSender(selfID),
        validator.NewAnyValidator(
            validator.NewOriginValidator(
                id.NewIdentityFilterIdentifierProvider(filter.IsValidCurrentEpochParticipant, idProvider),
            ),
            validator.ValidateTarget(log, selfID),  // ← second branch
        ),
    }
}
``` [1](#0-0) [2](#0-1) [3](#0-2) 

`NewAnyValidator` passes if **at least one** of its sub-validators returns `true`. The second branch, `ValidateTarget`, is implemented as:

```go
func (tv *TargetValidator) Validate(msg network.IncomingMessageScope) bool {
    if slices.Contains(msg.TargetIDs(), tv.target) {
        return true
    }
    ...
}
``` [4](#0-3) 

`msg.TargetIDs()` is populated directly from the raw wire-level `Message.TargetIDs` bytes field, which is set by the sender and is **not cryptographically signed or authenticated**:

```go
func NewIncomingScope(originId flow.Identifier, protocol ProtocolType, msg *Message, decodedPayload any) (*IncomingMessageScope, error) {
    ...
    targetIds, err := flow.ByteSlicesToIds(msg.TargetIDs)
    ...
    return &IncomingMessageScope{
        ...
        targetIds: targetIds,
    }, nil
}
``` [5](#0-4) 

In contrast, `msg.OriginId()` is derived from the libp2p peer ID, which **is** cryptographically authenticated (the peer's TLS/noise key). The `OriginValidator` checks this authenticated field against the staked identity set. But because `AnyValidator` short-circuits on the unauthenticated `ValidateTarget` branch, an attacker who is **not** a valid epoch participant can craft a message with the receiving node's `selfID` in the `TargetIDs` bytes, causing `ValidateTarget` to return `true` and the entire `AnyValidator` to accept the message — without ever passing the `OriginValidator` check.

The `TargetIDs` field is part of the `Message` protobuf that is serialized on the wire: [6](#0-5) 

There is no signature or MAC over this field. Any peer connected to the public network can set it to any value.

---

### Impact Explanation

An unprivileged, unstaked node (e.g., a malicious Observer or any peer that can connect to the public-facing libp2p endpoint of an Access Node or Follower) can inject arbitrary protocol messages — including sync requests, block proposals, or any other message type registered on the public network — into the engine processing pipeline of the target node. The receiving node's engine will process these messages as if they passed origin validation, because the `AnyValidator` accepted them via the forged `TargetIDs` field.

This is an unauthorized message injection: the sender identity check that is supposed to gate access to the engine pipeline is bypassed. Downstream impact depends on which engines are registered on the public network channels, but at minimum it allows an unstaked node to impersonate a legitimate protocol participant for the purpose of message delivery — the direct analog of the email sender spoofing in the reference report.

**Impact: 4/5** — Unauthorized access to the message processing pipeline of Access/Observer/Follower nodes by any peer on the public network.

---

### Likelihood Explanation

The public network endpoint of Access Nodes and Observer nodes is reachable by any peer. No staking, no special credentials, and no privileged position is required. The attacker only needs to:
1. Connect to the public libp2p endpoint.
2. Send a message with the receiving node's `selfID` encoded in the `TargetIDs` field.

This is trivially achievable by any node that can establish a libp2p connection, including unstaked Observer nodes and arbitrary internet peers.

**Likelihood: 4/5**

---

### Recommendation

The `ValidateTarget` branch must not be used as an alternative to origin identity verification in `publicNetworkMsgValidators`. The logical OR between an authenticated check (`OriginValidator`) and an unauthenticated check (`ValidateTarget`) nullifies the authenticated check entirely.

Options:
1. **Remove `ValidateTarget` from the `AnyValidator`** in `publicNetworkMsgValidators`. If targeted delivery is needed, it should be enforced only after origin identity is confirmed, not as an alternative to it.
2. **Require both conditions** (AND, not OR): the sender must be a valid staked node AND the message must be targeted at this node.
3. If messages from unstaked nodes must be accepted when targeted, the `TargetIDs` field must be cryptographically bound to the sender's authenticated peer identity (e.g., via a signature over the message including `TargetIDs`).

---

### Proof of Concept

1. Attacker operates any libp2p node (no staking required) and connects to the public network endpoint of a target Access Node or Observer node.
2. Attacker constructs a `Message` protobuf with:
   - `ChannelID`: any valid public channel (e.g., `PublicReceiveBlocks`)
   - `TargetIDs`: `[selfID_of_target_node]` — the known Flow node ID of the target
   - `Payload`: any encoded protocol message
3. Attacker sends this message via unicast or pubsub.
4. On the receiving side, `processUnicastStreamMessage` or `processPubSubMessages` calls `processAuthenticatedMessage`, which calls `processMessage`.
5. `processMessage` runs the registered `MessageValidator` list from `publicNetworkMsgValidators`.
6. `ValidateNotSender` passes (attacker ≠ target).
7. `AnyValidator` evaluates: `OriginValidator` returns `false` (attacker is not a staked epoch participant), but `ValidateTarget` returns `true` (because `TargetIDs` contains `selfID`).
8. `AnyValidator` returns `true` — the message is accepted and delivered to the engine. [7](#0-6) [8](#0-7)

### Citations

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

**File:** follower/follower_builder.go (L368-381)
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

**File:** cmd/observer/node_builder/observer_builder.go (L956-969)
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

**File:** network/validator/target_validator.go (L33-42)
```go
func (tv *TargetValidator) Validate(msg network.IncomingMessageScope) bool {
	if slices.Contains(msg.TargetIDs(), tv.target) {
		return true
	}
	tv.log.Debug().
		Hex("message_target_id", logging.ID(tv.target)).
		Hex("local_node_id", logging.ID(tv.target)).
		Hex("event_id", msg.EventID()).
		Msg("message not intended for target")
	return false
```

**File:** network/message/message_scope.go (L57-74)
```go
func NewIncomingScope(originId flow.Identifier, protocol ProtocolType, msg *Message, decodedPayload any) (*IncomingMessageScope, error) {
	eventId, err := EventId(channels.Channel(msg.ChannelID), msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("could not compute event id: %w", err)
	}

	targetIds, err := flow.ByteSlicesToIds(msg.TargetIDs)
	if err != nil {
		return nil, fmt.Errorf("could not convert target ids: %w", err)
	}
	return &IncomingMessageScope{
		eventId:        eventId,
		originId:       originId,
		msg:            msg,
		decodedPayload: decodedPayload,
		protocol:       protocol,
		targetIds:      targetIds,
	}, nil
```

**File:** network/message/message.pb.go (L141-148)
```go
	if len(m.TargetIDs) > 0 {
		for iNdEx := len(m.TargetIDs) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.TargetIDs[iNdEx])
			copy(dAtA[i:], m.TargetIDs[iNdEx])
			i = encodeVarintMessage(dAtA, i, uint64(len(m.TargetIDs[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
```

**File:** network/underlay/network.go (L1230-1244)
```go
	// if message channel is not public perform authorized sender validation
	if !channels.IsPublicChannel(channel) {
		messageType, err := n.authorizedSenderValidator.Validate(remotePeer, msg.Payload, channel, message.ProtocolTypeUnicast)
		if err != nil {
			n.logger.
				Error().
				Err(err).
				Str("peer_id", p2plogging.PeerId(remotePeer)).
				Str("type", messageType).
				Str("channel", msg.ChannelID).
				Msg("unicast authorized sender validation failed")
			return
		}
	}
	n.processAuthenticatedMessage(msg, remotePeer, message.ProtocolTypeUnicast)
```

**File:** network/underlay/network.go (L1247-1261)
```go
// processAuthenticatedMessage processes a message and a source (indicated by its peer ID) and eventually passes it to the overlay
// In particular, it populates the `OriginID` field of the message with a Flow ID translated from this source.
func (n *Network) processAuthenticatedMessage(msg *message.Message, peerID peer.ID, protocol message.ProtocolType) {
	originId, err := n.identityTranslator.GetFlowID(peerID)
	if err != nil {
		// this error should never happen. by the time the message gets here, the peer should be
		// authenticated which means it must be known
		n.logger.Error().
			Err(err).
			Str("peer_id", p2plogging.PeerId(peerID)).
			Bool(logging.KeySuspicious, true).
			Msg("dropped message from unknown peer")
		return
	}

```
