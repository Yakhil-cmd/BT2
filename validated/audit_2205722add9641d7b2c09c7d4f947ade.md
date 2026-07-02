### Title
Overly Broad Role Authorization on `SyncCommittee` Channel Allows Any Staked Node Role to Trigger Sync State Mutations on Consensus Nodes — (`network/message/authorization.go`)

### Summary
The `SyncRequest`, `RangeRequest`, and `BatchRequest` message authorization configs on the `SyncCommittee` channel grant `flow.Roles()` — all five node roles — as authorized senders. This is the direct analog of the Solidity `onlyPermit` over-inclusion bug: roles that have no legitimate reason to send sync requests to consensus nodes (e.g., Access nodes, Verification nodes) are nonetheless authorized to do so. Any staked node of any role can send these messages to consensus nodes, causing the receiving node's sync core to process attacker-controlled heights and block ID lists, and triggering probabilistic ALSP misbehavior reports against innocent peers.

### Finding Description

In `network/message/authorization.go`, the authorization configs for the three sync protocol messages on `channels.SyncCommittee` are:

```go
authorizationConfigs[SyncRequest] = MsgAuthConfig{
    Config: map[channels.Channel]ChannelAuthConfig{
        channels.SyncCommittee: {
            AuthorizedRoles:  flow.Roles(),   // ALL 5 roles
            ...
        },
    },
}
authorizationConfigs[RangeRequest] = MsgAuthConfig{
    Config: map[channels.Channel]ChannelAuthConfig{
        channels.SyncCommittee: {
            AuthorizedRoles:  flow.Roles(),   // ALL 5 roles
            ...
        },
    },
}
authorizationConfigs[BatchRequest] = MsgAuthConfig{
    Config: map[channels.Channel]ChannelAuthConfig{
        channels.SyncCommittee: {
            AuthorizedRoles:  flow.Roles(),   // ALL 5 roles
            ...
        },
    },
}
```

`flow.Roles()` returns `[Collection, Consensus, Execution, Verification, Access]`.

The `SyncCommittee` channel is subscribed to by all roles (`channelRoleMap[SyncCommittee] = flow.Roles()`), but the *sending* authorization for sync requests should be restricted to only the roles that legitimately participate in the consensus sync protocol — i.e., Consensus nodes. Access nodes, Verification nodes, and Execution nodes have no protocol-defined reason to send `SyncRequest`, `RangeRequest`, or `BatchRequest` to consensus nodes on this channel.

The receiving handler `RequestHandler.onSyncRequest` unconditionally calls `r.core.HandleHeight(finalizedHeader, req.Height)` with the attacker-supplied height, and `RequestHandler.onRangeRequest`/`onBatchRequest` process attacker-supplied block ID lists. The ALSP validation is only probabilistic (default 1% for `SyncRequest`, configurable base probability for `RangeRequest`/`BatchRequest`), not a hard block.

Contrast this with the `SyncResponse` config, which correctly restricts `AuthorizedRoles` to `flow.RoleList{flow.RoleConsensus}` on `SyncCommittee` — demonstrating that the designers knew responses should be role-restricted, but did not apply the same principle to requests.

The attacker entry path is:
1. Attacker operates a staked Access node (or any other non-Consensus staked node).
2. Attacker publishes crafted `SyncRequest` / `RangeRequest` / `BatchRequest` messages on the `SyncCommittee` GossipSub channel.
3. `AuthorizedSenderValidator.isAuthorizedSender` passes because `flow.Roles()` includes `flow.RoleAccess`.
4. The message reaches `RequestHandler.processAvailableRequests`, which calls `r.core.HandleHeight` with the attacker-controlled height, or processes attacker-controlled block ID lists.
5. The ALSP check fires only probabilistically (1% by default), so the attacker can sustain the attack across thousands of messages before being penalized.

### Impact Explanation

- **Sync state manipulation**: A staked Access node can send `SyncRequest` messages with arbitrary heights to all consensus nodes, causing `core.HandleHeight` to queue spurious missing-height entries in the sync core's pending download queue. This can cause consensus nodes to waste resources attempting to download non-existent or irrelevant blocks.
- **Batch/Range amplification**: `BatchRequest` with large `BlockIDs` lists and `RangeRequest` with large height ranges cause the receiving consensus node to perform expensive block lookups and respond with `BlockResponse` messages. The ALSP probabilistic check only fires at ~1% base probability for normal-sized requests, meaning an attacker can sustain high-volume requests with minimal penalty accumulation.
- **Misleading role semantics**: The over-broad ACL obscures which roles are actually supposed to participate in consensus sync, making it harder to reason about the trust model — the exact analog of the Solidity `onlyPermit` including `owner` when it should not.

### Likelihood Explanation

Any operator of a staked Access node (the most permissive and publicly accessible node type) can exploit this without any privileged access. Access nodes are the standard entry point for external parties. The attack requires only a valid staked identity on the network, which is a realistic attacker precondition.

### Recommendation

Restrict `AuthorizedRoles` for `SyncRequest`, `RangeRequest`, and `BatchRequest` on `channels.SyncCommittee` to only `flow.RoleList{flow.RoleConsensus}`, matching the principle already applied to `SyncResponse`. Each role should only be authorized to send messages it has a legitimate protocol reason to send. The current design grants all roles the same send permissions as Consensus nodes on the sync channel, violating the principle of least privilege and mirroring the exact `onlyPermit` over-inclusion described in the external report.

### Proof of Concept

1. Attacker runs a staked Access node registered in the protocol state.
2. Attacker publishes on `channels.SyncCommittee` via GossipSub:
   ```go
   // Attacker-controlled payload
   req := &messages.BatchRequest{
       Nonce:    attackerNonce,
       BlockIDs: make([]flow.Identifier, 64), // max size, triggers high-probability ALSP
   }
   ```
3. `AuthorizedSenderValidator.isAuthorizedSender` is called with `identity.Role = flow.RoleAccess`.
4. `conf.EnsureAuthorized(flow.RoleAccess, channels.SyncCommittee, ProtocolTypePubSub)` succeeds because `authorizationConfigs[BatchRequest].Config[channels.SyncCommittee].AuthorizedRoles = flow.Roles()` which contains `flow.RoleAccess`.
5. Message reaches `RequestHandler.onBatchRequest`, which performs block lookups for all 64 attacker-specified block IDs.
6. ALSP fires probabilistically at `batchRequestBaseProb * (64+1) / 64 ≈ 1%` — insufficient to stop a sustained attack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** network/message/authorization.go (L105-168)
```go
	authorizationConfigs[SyncRequest] = MsgAuthConfig{
		Name: SyncRequest,
		Type: func() any {
			return new(messages.SyncRequest)
		},
		Config: map[channels.Channel]ChannelAuthConfig{
			channels.SyncCommittee: {
				AuthorizedRoles:  flow.Roles(),
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
			channels.SyncClusterPrefix: {
				AuthorizedRoles:  flow.RoleList{flow.RoleCollection},
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
		},
	}
	authorizationConfigs[SyncResponse] = MsgAuthConfig{
		Name: SyncResponse,
		Type: func() any {
			return new(messages.SyncResponse)
		},
		Config: map[channels.Channel]ChannelAuthConfig{
			channels.SyncCommittee: {
				AuthorizedRoles:  flow.RoleList{flow.RoleConsensus},
				AllowedProtocols: Protocols{ProtocolTypeUnicast},
			},
			channels.SyncClusterPrefix: {
				AuthorizedRoles:  flow.RoleList{flow.RoleCollection},
				AllowedProtocols: Protocols{ProtocolTypeUnicast},
			},
		},
	}
	authorizationConfigs[RangeRequest] = MsgAuthConfig{
		Name: RangeRequest,
		Type: func() any {
			return new(messages.RangeRequest)
		},
		Config: map[channels.Channel]ChannelAuthConfig{
			channels.SyncCommittee: {
				AuthorizedRoles:  flow.Roles(),
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
			channels.SyncClusterPrefix: {
				AuthorizedRoles:  flow.RoleList{flow.RoleCollection},
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
		},
	}
	authorizationConfigs[BatchRequest] = MsgAuthConfig{
		Name: BatchRequest,
		Type: func() any {
			return new(messages.BatchRequest)
		},
		Config: map[channels.Channel]ChannelAuthConfig{
			channels.SyncCommittee: {
				AuthorizedRoles:  flow.Roles(),
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
			channels.SyncClusterPrefix: {
				AuthorizedRoles:  flow.RoleList{flow.RoleCollection},
				AllowedProtocols: Protocols{ProtocolTypePubSub},
			},
		},
	}
```

**File:** network/validator/authorized_sender_validator.go (L124-152)
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
}
```

**File:** engine/common/synchronization/request_handler.go (L105-147)
```go
// setupRequestMessageHandler initializes the inbound queues and the MessageHandler for UNTRUSTED requests.
func (r *RequestHandler) setupRequestMessageHandler() {
	// RequestHeap deduplicates requests by keeping only one sync request for each requester.
	r.pendingSyncRequests = NewRequestHeap(defaultSyncRequestQueueCapacity)
	r.pendingRangeRequests = NewRequestHeap(defaultRangeRequestQueueCapacity)
	r.pendingBatchRequests = NewRequestHeap(defaultBatchRequestQueueCapacity)

	// define message queueing behaviour
	r.requestMessageHandler = engine.NewMessageHandler(
		r.log,
		engine.NewNotifier(),
		engine.Pattern{
			Match: func(msg *engine.Message) bool {
				_, ok := msg.Payload.(*flow.SyncRequest)
				if ok {
					r.metrics.MessageReceived(metrics.EngineSynchronization, metrics.MessageSyncRequest)
				}
				return ok
			},
			Store: r.pendingSyncRequests,
		},
		engine.Pattern{
			Match: func(msg *engine.Message) bool {
				_, ok := msg.Payload.(*flow.RangeRequest)
				if ok {
					r.metrics.MessageReceived(metrics.EngineSynchronization, metrics.MessageRangeRequest)
				}
				return ok
			},
			Store: r.pendingRangeRequests,
		},
		engine.Pattern{
			Match: func(msg *engine.Message) bool {
				_, ok := msg.Payload.(*flow.BatchRequest)
				if ok {
					r.metrics.MessageReceived(metrics.EngineSynchronization, metrics.MessageBatchRequest)
				}
				return ok
			},
			Store: r.pendingBatchRequests,
		},
	)
}
```

**File:** engine/common/synchronization/engine.go (L612-652)
```go
}

// validateSyncRequestForALSP checks if a sync request should be reported as a misbehavior and sends misbehavior report to ALSP.
// The misbehavior is ambiguous to detect as malicious behavior because there is no way to know for sure if the sender is sending
// a sync request maliciously or not, so we use a probabilistic approach to report the misbehavior.
//
// Args:
// - originID: the sender of the sync request
// Returns:
// - error: If an error is encountered while validating the sync request. Error is assumed to be irrecoverable because of internal processes that didn't allow validation to complete.
func (e *Engine) validateSyncRequestForALSP(originID flow.Identifier) error {
	// Generate a random integer between 0 and spamProbabilityMultiplier (exclusive)
	n, err := rand.Uint32n(spamProbabilityMultiplier)
	if err != nil {
		return fmt.Errorf("failed to generate random number from %x: %w", originID[:], err)
	}

	// to avoid creating a misbehavior report for every sync request received, use a probabilistic approach.
	// Create a report with a probability of spamDetectionConfig.syncRequestProb
	if float32(n) < e.spamDetectionConfig.syncRequestProb*spamProbabilityMultiplier {

		// create misbehavior report
		e.log.Debug().
			Hex("origin_id", logging.ID(originID)).
			Str(logging.KeyLoad, "true").
			Str("reason", alsp.ResourceIntensiveRequest.String()).
			Msg("creating probabilistic ALSP report")

		report, err := alsp.NewMisbehaviorReport(originID, alsp.ResourceIntensiveRequest)
		if err != nil {
			// failing to create the misbehavior report is unlikely. If an error is encountered while
			// creating the misbehavior report it indicates a bug and processing can not proceed.
			return fmt.Errorf("failed to create misbehavior report from %x: %w", originID[:], err)
		}
		e.con.ReportMisbehavior(report)
		return nil
	}

	// passed all validation checks with no misbehavior detected
	return nil
}
```

**File:** model/flow/role.go (L73-75)
```go
func Roles() RoleList {
	return []Role{RoleCollection, RoleConsensus, RoleExecution, RoleVerification, RoleAccess}
}
```

**File:** network/channels/channels.go (L182-183)
```go
	channelRoleMap[SyncCommittee] = flow.Roles()

```

**File:** config/default-config.yml (L661-681)
```yaml
  alsp-sync-engine-batch-request-base-prob: 0.01
  # Base probability in [0,1] that's used in creating the final probability of creating a
  # misbehavior report for a RangeRequest message. This is why the word "base" is used in the name of this field,
  # since it's not the final probability and there are other factors that determine the final probability.
  # The reason for this is that we want to increase the probability of creating a misbehavior report for a large range.
  # Create misbehavior report for about 0.2% of RangeRequest messages for normal range requests (i.e. not too large)
  # and about 15% of RangeRequest messages for very large range requests.
  # The final probability is calculated as follows:
  # rangeRequestBaseProb * ((rangeRequest.ToHeight-rangeRequest.FromHeight) + 1) / synccore.DefaultConfig().MaxSize
  # Example 1 (small range) if the range request is for 10 blocks and rangeRequestBaseProb is 0.01, then the probability of
  # creating a misbehavior report is:
  # rangeRequestBaseProb * (10+1) / synccore.DefaultConfig().MaxSize
  # = 0.01 * 11 / 64 = 0.00171875 = 0.171875%
  # Example 2 (large range) if the range request is for 1000 blocks and rangeRequestBaseProb is 0.01, then the probability of
  # creating a misbehavior report is:
  # rangeRequestBaseProb * (1000+1) / synccore.DefaultConfig().MaxSize
  # = 0.01 * 1001 / 64 = 0.15640625 = 15.640625%
  alsp-sync-engine-range-request-base-prob: 0.01
  # Probability in [0,1] of creating a misbehavior report for a SyncRequest message.
  # create misbehavior report for 1% of SyncRequest messages
  alsp-sync-engine-sync-request-prob: 0.01
```
