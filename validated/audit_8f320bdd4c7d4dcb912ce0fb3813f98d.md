### Title
Unauthenticated EN gRPC Connection + Missing EventCollection Hash Verification Enables MITM Event Injection - (`engine/access/rpc/backend/events/provider/execution_node.go`, `engine/access/rpc/connection/connection.go`)

---

### Summary

The access node's `GetExecutionAPIClient` unconditionally passes `nil` as the `networkPubKey` to `Manager.GetConnection`, forcing every connection to an execution node to use `grpc.WithTransportCredentials(insecure.NewCredentials())` — plaintext gRPC with no TLS and no server identity verification. A network-adjacent attacker who can intercept TCP traffic between the access node and an EN can substitute an arbitrary `GetEventsForBlockIDsResponse`. The access node's `verifyAndConvertToAccessEvents` function only validates that the returned block IDs and heights match the request; it never recomputes the events' Merkle root and compares it against the `EventCollection` hash committed to in the execution receipt's chunks. A bridge relayer consuming the Access API's event stream would therefore receive and act on fabricated `EVM.TransactionExecuted` payloads.

---

### Finding Description

**Root cause 1 — Hardcoded insecure transport for EN connections**

`ConnectionFactoryImpl.GetExecutionAPIClient` calls `Manager.GetConnection` with a hardcoded `nil` public key: [1](#0-0) 

`Manager.createConnection` branches on whether `networkPubKey != nil`. Because it is always `nil` for EN connections, the `else` branch is always taken: [2](#0-1) 

The `ConnectionFactory` interface signature for `GetExecutionAPIClient` does not even accept a `networkPubKey` parameter, unlike `GetCollectionAPIClient` and `GetAccessAPIClientWithPort`: [3](#0-2) 

**Root cause 2 — No event payload integrity check against execution receipt commitment**

After receiving the EN response, `verifyAndConvertToAccessEvents` checks only that the number of results matches, that each block ID is in the requested set, and that the block height matches: [4](#0-3) 

It never recomputes `flow.EventsMerkleRootHash(events)` and compares it against `chunk.EventCollection` from the locally-stored execution receipt. The `EventCollection` field in each `ChunkBody` is precisely this Merkle root: [5](#0-4) 

The verification node's chunk verifier *does* perform this check: [6](#0-5) 

The access node already holds execution receipts (used by `ExecutionNodesForBlockID` to select ENs): [7](#0-6) 

but `verifyAndConvertToAccessEvents` never consults them for payload integrity.

**Attack path**

`tryGetEvents` dials the EN address from `IdentitySkeleton.Address` over plaintext: [8](#0-7) 

A MITM proxy intercepts the TCP stream, replaces the protobuf-encoded `GetEventsForBlockIDsResponse` with a crafted one containing a fabricated `EVM.TransactionExecuted` event (e.g., inflated `amount` field, attacker-controlled `recipient`). The access node's `verifyAndConvertToAccessEvents` accepts the response because block ID and height still match. The fabricated events are returned to any caller of the Access API's `GetEventsForBlockIDs` RPC, including bridge relayers.

---

### Impact Explanation

A bridge relayer that reads `EVM.TransactionExecuted` events via the Access API to determine how many ERC-20 tokens to release from escrow will act on the injected payload. If the injected event claims a larger `amount` than was actually locked, the relayer releases more tokens than were deposited, directly violating bridge escrow accounting and enabling theft of escrowed assets. This matches the Critical scope: *bridge relayer reads inflated transfer amounts from the injected event payload and releases more escrowed ERC-20 tokens than were locked*.

---

### Likelihood Explanation

- The EN gRPC port is reachable over the network (access nodes connect to ENs operated by different parties).
- No TLS means any on-path attacker (BGP hijack, compromised router, cloud VPC peer, shared hosting) can read and rewrite the stream.
- The missing `EventCollection` hash check means the access node provides no cryptographic defense even if TLS were added later at the transport layer but the application-layer check remained absent.
- The attack is fully passive from the EN's perspective; the legitimate EN never detects it.

---

### Recommendation

1. **Add TLS with public-key pinning to EN connections.** Extend the `ConnectionFactory.GetExecutionAPIClient` interface to accept a `crypto.PublicKey` (matching the pattern of `GetCollectionAPIClient`), populate it from `IdentitySkeleton.NetworkPubKey`, and pass it to `Manager.GetConnection`. This mirrors the existing `DefaultClientTLSConfig` / `verifyPeerCertificateFunc` path already used for collection nodes.

2. **Verify event payloads against the committed `EventCollection` hash.** In `verifyAndConvertToAccessEvents` (or its caller), after converting events, recompute `flow.EventsMerkleRootHash(events)` and compare it against `chunk.EventCollection` from the locally-stored execution receipt for the corresponding block. Reject the response if the hashes differ.

---

### Proof of Concept

1. Start a Flow localnet with one access node and one execution node.
2. Insert a transparent TCP proxy (e.g., `mitmproxy` in raw TCP mode) on the path between the access node and the EN's gRPC port.
3. Configure the proxy to intercept `GetEventsForBlockIDsResponse` messages and replace any `EVM.TransactionExecuted` event payload with a crafted CCF-encoded payload containing an inflated token amount.
4. Submit an EVM token-lock transaction on the localnet.
5. Call `GetEventsForBlockIDs` on the access node for the block containing the lock transaction.
6. Assert that the access node returns the injected (inflated) event payload without error — demonstrating that neither the transport layer nor `verifyAndConvertToAccessEvents` detects the substitution.
7. Feed the returned events to a bridge relayer stub and observe it computing a release amount larger than the locked amount.

### Citations

**File:** engine/access/rpc/connection/connection.go (L19-31)
```go
type ConnectionFactory interface {
	// GetCollectionAPIClient gets an access API client for the specified address using the default CollectionGRPCPort, networkPubKey is optional,
	// and it is used for secure gRPC connection. Can be nil for an unsecured connection.
	// The returned io.Closer should close the connection after the call if no error occurred during client creation.
	GetCollectionAPIClient(address string, networkPubKey crypto.PublicKey) (access.AccessAPIClient, io.Closer, error)
	// GetAccessAPIClientWithPort gets an access API client for the specified address with port, networkPubKey is optional,
	// and it is used for secure gRPC connection. Can be nil for an unsecured connection.
	// The returned io.Closer should close the connection after the call if no error occurred during client creation.
	GetAccessAPIClientWithPort(address string, networkPubKey crypto.PublicKey) (access.AccessAPIClient, io.Closer, error)
	// GetExecutionAPIClient gets an execution API client for the specified address using the default ExecutionGRPCPort.
	// The returned io.Closer should close the connection after the call if no error occurred during client creation.
	GetExecutionAPIClient(address string) (execution.ExecutionAPIClient, io.Closer, error)
}
```

**File:** engine/access/rpc/connection/connection.go (L133-145)
```go
func (cf *ConnectionFactoryImpl) GetExecutionAPIClient(address string) (execution.ExecutionAPIClient, io.Closer, error) {
	grpcAddress, err := getGRPCAddress(address, cf.ExecutionConfig.GRPCPort)
	if err != nil {
		return nil, nil, err
	}

	conn, closer, err := cf.Manager.GetConnection(grpcAddress, cf.ExecutionConfig, nil)
	if err != nil {
		return nil, nil, err
	}

	return execution.NewExecutionAPIClient(conn), closer, nil
}
```

**File:** engine/access/rpc/connection/manager.go (L160-168)
```go
	if networkPubKey != nil {
		tlsConfig, err := grpcutils.DefaultClientTLSConfig(networkPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get default TLS client config using public flow networking key %s %w", networkPubKey.String(), err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
```

**File:** engine/access/rpc/backend/events/provider/execution_node.go (L148-160)
```go
func (e *ENEventProvider) tryGetEvents(
	ctx context.Context,
	execNode *flow.IdentitySkeleton,
	req *execproto.GetEventsForBlockIDsRequest,
) (*execproto.GetEventsForBlockIDsResponse, error) {
	execRPCClient, closer, err := e.connFactory.GetExecutionAPIClient(execNode.Address)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	return execRPCClient.GetEventsForBlockIDs(ctx, req)
}
```

**File:** engine/access/rpc/backend/events/provider/execution_node.go (L162-206)
```go
// verifyAndConvertToAccessEvents converts execution node api result to access node api result,
// and verifies that the results contains results from each block that was requested
func verifyAndConvertToAccessEvents(
	execEvents []*execproto.GetEventsForBlockIDsResponse_Result,
	requestedBlockInfos []BlockMetadata,
	from entities.EventEncodingVersion,
	to entities.EventEncodingVersion,
) ([]flow.BlockEvents, error) {
	if len(execEvents) != len(requestedBlockInfos) {
		return nil, errors.New("number of results does not match number of blocks requested")
	}

	requestedBlockInfoSet := map[string]BlockMetadata{}
	for _, header := range requestedBlockInfos {
		requestedBlockInfoSet[header.ID.String()] = header
	}

	results := make([]flow.BlockEvents, len(execEvents))

	for i, result := range execEvents {
		blockInfo, expected := requestedBlockInfoSet[hex.EncodeToString(result.GetBlockId())]
		if !expected {
			return nil, fmt.Errorf("unexpected blockID from exe node %x", result.GetBlockId())
		}
		if result.GetBlockHeight() != blockInfo.Height {
			return nil, fmt.Errorf("unexpected block height %d for block %x from exe node",
				result.GetBlockHeight(),
				result.GetBlockId())
		}

		events, err := convert.MessagesToEventsWithEncodingConversion(result.GetEvents(), from, to)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal events in event %d with encoding version %s: %w",
				i, to.String(), err)
		}

		results[i] = flow.BlockEvents{
			BlockID:        blockInfo.ID,
			BlockHeight:    blockInfo.Height,
			BlockTimestamp: blockInfo.Timestamp,
			Events:         events,
		}
	}

	return results, nil
```

**File:** model/flow/chunk.go (L25-48)
```go
type ChunkBody struct {
	CollectionIndex uint

	// execution info
	StartState      StateCommitment // start state when starting executing this chunk
	EventCollection Identifier      // Events generated by executing results
	// ServiceEventCount defines how many service events were emitted in this chunk.
	// By reading these fields from the prior chunks in the same ExecutionResult, we can
	// compute exactly what service events were emitted in this chunk.
	//
	// Let C be this chunk, K be the set of chunks in the ExecutionResult containing C.
	// Then the service event indices for C are given by:
	//    StartIndex = ∑Ci.ServiceEventCount : Ci ∈ K, Ci.Index < C.Index
	//    EndIndex = StartIndex + C.ServiceEventCount
	// The service events for C are given by:
	//    ExecutionResult.ServiceEvents[StartIndex:EndIndex]
	//
	ServiceEventCount uint16
	BlockID           Identifier // Block id of the execution result this chunk belongs to

	// Computation consumption info
	TotalComputationUsed uint64 // total amount of computation used by running all txs in this chunk
	NumberOfTransactions uint64 // number of transactions inside the collection
}
```

**File:** module/chunks/chunkVerifier.go (L294-319)
```go
	eventsHash, err := flow.EventsMerkleRootHash(events)
	if err != nil {
		return nil, fmt.Errorf("cannot calculate events collection hash: %w", err)
	}
	if chunk.EventCollection != eventsHash {
		collectionID := ""
		if chunkDataPack.Collection != nil {
			collectionID = chunkDataPack.Collection.ID().String()
		}
		for i, event := range events {
			fcv.logger.Warn().Int("list_index", i).
				Str("event_id", event.ID().String()).
				Hex("event_fingerprint", fingerprint.Fingerprint(event)).
				Str("event_type", string(event.Type)).
				Str("event_tx_id", event.TransactionID.String()).
				Uint32("event_tx_index", event.TransactionIndex).
				Uint32("event_index", event.EventIndex).
				Hex("event_payload", event.Payload).
				Str("block_id", chunk.BlockID.String()).
				Str("collection_id", collectionID).
				Str("result_id", result.ID().String()).
				Uint64("chunk_index", chunk.Index).
				Msg("not matching events debug")
		}

		return nil, chmodels.NewCFInvalidEventsCollection(chunk.EventCollection, eventsHash, chIndex, execResID, events)
```

**File:** engine/common/rpc/execution_node_identities_provider.go (L96-133)
```go
		// try to find at least minExecutionNodesCnt execution node ids from the execution receipts for the given blockID
		for attempt := range maxAttemptsForExecutionReceipt {
			executorIDs, err = e.findAllExecutionNodes(blockID)
			if err != nil {
				return nil, err
			}

			if len(executorIDs) >= minExecutionNodesCnt {
				break
			}

			// log the attempt
			e.log.Debug().Int("attempt", attempt).Int("max_attempt", maxAttemptsForExecutionReceipt).
				Int("execution_receipts_found", len(executorIDs)).
				Str("block_id", blockID.String()).
				Msg("insufficient execution receipts")

			// if one or less execution receipts may have been received then re-query
			// in the hope that more might have been received by now

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond << time.Duration(attempt)):
				// retry after an exponential backoff
			}
		}

		receiptCnt := len(executorIDs)
		// if less than minExecutionNodesCnt execution receipts have been received so far, then return random ENs
		if receiptCnt < minExecutionNodesCnt {
			newExecutorIDs, err := e.state.AtBlockID(blockID).Identities(filter.HasRole[flow.Identity](flow.RoleExecution))
			if err != nil {
				return nil, fmt.Errorf("failed to retreive execution IDs for block ID %v: %w", blockID, err)
			}
			executorIDs = newExecutorIDs.NodeIDs()
		}
	}
```
