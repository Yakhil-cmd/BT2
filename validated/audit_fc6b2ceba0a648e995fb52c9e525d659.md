### Title
Unauthenticated Plaintext gRPC to Execution Node Allows MITM Injection of Fabricated Event Payloads — (`engine/access/rpc/backend/events/provider/execution_node.go`)

---

### Summary

`GetExecutionAPIClient` opens a **plaintext, unauthenticated gRPC connection** to the Execution Node (EN). The EN's `NetworkPubKey` is present in `IdentitySkeleton` but is never passed to the connection factory. After receiving the response, `verifyAndConvertToAccessEvents` only checks block ID and block height — it never verifies event payloads against the `EventCollection` hash committed to in the sealed execution receipt. A network-adjacent attacker who can intercept the plaintext channel can inject a fabricated `GetEventsForBlockIDsResponse` carrying arbitrary event payloads (e.g., inflated `EVM.TransactionExecuted` amounts), and the access node will accept and serve them verbatim.

---

### Finding Description

**Root cause 1 — Plaintext connection, `networkPubKey` hardcoded to `nil`:**

`GetExecutionAPIClient` passes `nil` as the network public key: [1](#0-0) 

```go
execRPCClient, closer, err := e.connFactory.GetExecutionAPIClient(execNode.Address)
```

The interface signature accepts only an address — no key: [2](#0-1) 

The implementation forwards `nil` to `Manager.GetConnection`: [3](#0-2) 

In `createConnection`, a `nil` key unconditionally selects `insecure.NewCredentials()`: [4](#0-3) 

The EN's `NetworkPubKey` is available in `IdentitySkeleton` (populated from the protocol state / EpochSetup event): [5](#0-4) 

but `GetExecutionAPIClient` never accepts or uses it, unlike `GetCollectionAPIClient` and `GetAccessAPIClientWithPort` which do accept a `networkPubKey` parameter.

**Root cause 2 — No event payload verification against execution receipt commitment:**

After receiving the EN's response, `verifyAndConvertToAccessEvents` checks only that the returned block IDs are in the requested set and that block heights match: [6](#0-5) 

It never checks event payloads against the `EventCollection` hash committed to in each chunk of the sealed execution result. That hash exists precisely for this purpose: [7](#0-6) 

The access node stores sealed execution receipts (and therefore has access to the per-chunk `EventCollection` commitment), but the event provider never consults it.

---

### Impact Explanation

A network-adjacent attacker who can intercept the plaintext TCP stream between the access node and EN can:

1. Intercept the `GetEventsForBlockIDsResponse`.
2. Replace event payloads — e.g., change the `payload` bytes of an `EVM.TransactionExecuted` event to report an inflated token transfer amount or a different recipient address.
3. Keep block IDs and heights intact so `verifyAndConvertToAccessEvents` passes.
4. The access node serves the fabricated events to any downstream consumer (REST, gRPC, WebSocket subscription).

A bridge relayer that reads `EVM.TransactionExecuted` events from the access node API and uses the reported amount to release escrowed ERC-20 tokens on the destination chain would release more tokens than were actually locked — a direct, concrete financial loss matching the "escrow mis-accounting" critical scope.

---

### Likelihood Explanation

- The access node and EN are typically operated by different entities and communicate over the public internet or a shared cloud network.
- The connection is plaintext gRPC (port 9000 by default), trivially interceptable via BGP hijacking, ARP poisoning, or compromised cloud/ISP infrastructure.
- No cryptographic proof is required to forge a valid-looking response — the attacker only needs to preserve block IDs and heights.
- The attack is locally reproducible: insert a transparent TCP proxy between the access node and EN in a localnet, rewrite the protobuf response body, and observe the access node accepting and forwarding the fabricated events.

---

### Recommendation

1. **Authenticate the EN connection**: Pass `execNode.NetworkPubKey` to `GetExecutionAPIClient` (matching the pattern already used by `GetCollectionAPIClient`), and use it to establish a mutually-authenticated TLS connection via `grpcutils.DefaultClientTLSConfig`.
2. **Verify event payloads against the sealed execution receipt**: After fetching events from the EN, retrieve the sealed `ExecutionResult` for each block, compute the `EventCollection` hash over the returned events per chunk, and compare it against `chunk.EventCollection`. Reject any response where the hashes do not match.

---

### Proof of Concept

1. Start a Flow localnet with one access node and one EN.
2. Insert a transparent TCP proxy (e.g., `mitmproxy` in transparent mode) on the path between the access node (port 9000 toward the EN).
3. Write a proxy script that intercepts `GetEventsForBlockIDsResponse`, decodes the protobuf, doubles the token amount in the `EVM.TransactionExecuted` event payload, and re-encodes it. Block IDs and heights are left unchanged.
4. Submit an EVM token transfer transaction and wait for it to be sealed.
5. Query the access node for events on that block. Observe that the access node returns the inflated amount without error — `verifyAndConvertToAccessEvents` passes because block ID and height are intact.
6. A bridge relayer consuming this response would release twice the escrowed tokens.

### Citations

**File:** engine/access/rpc/backend/events/provider/execution_node.go (L153-153)
```go
	execRPCClient, closer, err := e.connFactory.GetExecutionAPIClient(execNode.Address)
```

**File:** engine/access/rpc/backend/events/provider/execution_node.go (L170-204)
```go
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
```

**File:** engine/access/rpc/connection/connection.go (L28-30)
```go
	// GetExecutionAPIClient gets an execution API client for the specified address using the default ExecutionGRPCPort.
	// The returned io.Closer should close the connection after the call if no error occurred during client creation.
	GetExecutionAPIClient(address string) (execution.ExecutionAPIClient, io.Closer, error)
```

**File:** engine/access/rpc/connection/connection.go (L133-144)
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

**File:** model/flow/identity.go (L19-33)
```go
type IdentitySkeleton struct {
	// NodeID uniquely identifies a particular node. A node's ID is fixed for
	// the duration of that node's participation in the network.
	NodeID Identifier
	// Address is the network address where the node can be reached.
	Address string
	// Role is the node's role in the network and defines its abilities and
	// responsibilities.
	Role Role
	// InitialWeight is a 'trust score' initially assigned by EpochSetup event after
	// the staking phase. The initial weights define the supermajority thresholds for
	// the cluster and security node consensus throughout the Epoch.
	InitialWeight uint64
	StakingPubKey crypto.PublicKey
	NetworkPubKey crypto.PublicKey
```

**File:** model/flow/chunk.go (L25-31)
```go
type ChunkBody struct {
	CollectionIndex uint

	// execution info
	StartState      StateCommitment // start state when starting executing this chunk
	EventCollection Identifier      // Events generated by executing results
	// ServiceEventCount defines how many service events were emitted in this chunk.
```
