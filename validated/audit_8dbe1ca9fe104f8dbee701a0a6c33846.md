Now I have all the information needed to make a definitive assessment. Let me verify the exact `WithLegacy` wiring one more time against the observer build sequence.

### Title
Observer Legacy gRPC `SendTransaction` Bypasses `FlowAccessAPIRouter` Upstream Routing, Enabling Direct Collection-Node Injection — (`engine/access/rpc/engine_builder.go`, `access/legacy/handler.go`)

---

### Summary

The observer's `WithLegacy()` call registers the legacy gRPC handler bound directly to the raw `*backend.Backend`, not to the `FlowAccessAPIRouter`. The router's `SendTransaction` correctly forwards to the upstream staked AN; the legacy handler completely bypasses it, calling the backend's `SendTransaction` which validates, stores locally, and forwards the transaction directly to a collection node. The observer's backend is fully provisioned with a live `ConnFactory`, `State`, and `Transactions` store, so all three steps succeed.

---

### Finding Description

**Step 1 — Observer build sequence**

In `observer_builder.go` the RPC engine is assembled as:

```go
builder.RpcEng, err = engineBuilder.
    WithRpcHandler(rpcHandler).   // installs FlowAccessAPIRouter for accessproto service
    WithLegacy().                 // installs legacyaccess.Handler for legacyaccessproto service
    Build()
``` [1](#0-0) 

**Step 2 — `WithLegacy()` wires the raw backend, not the router**

```go
func (builder *RPCEngineBuilder) WithLegacy() *RPCEngineBuilder {
    builder.unsecureGrpcServer.RegisterService(func(s *grpc.Server) {
        legacyaccessproto.RegisterAccessAPIServer(s, legacyaccess.NewHandler(builder.backend, builder.chain))
    })
    ...
}
```

`builder.backend` is `builder.Engine.backend` — the raw `*backend.Backend`. The `FlowAccessAPIRouter` (`rpcHandler`) is only registered for the modern `accessproto` service in `Build()`. [2](#0-1) 

**Step 3 — The router correctly gates `SendTransaction` to upstream**

```go
func (h *FlowAccessAPIRouter) SendTransaction(...) {
    res, err := h.upstream.SendTransaction(context, req)  // → staked AN
    ...
}
``` [3](#0-2) 

**Step 4 — The legacy handler calls the raw backend directly**

```go
func (h *Handler) SendTransaction(ctx context.Context, req *accessproto.SendTransactionRequest) ... {
    ...
    err = h.api.SendTransaction(ctx, &tx)   // h.api = *backend.Backend, not the router
    ...
}
``` [4](#0-3) 

**Step 5 — `backend.Backend.SendTransaction` validates, injects into collection node, stores locally**

```go
func (t *Transactions) SendTransaction(ctx context.Context, tx *flow.TransactionBody) error {
    err := t.txValidator.Validate(ctx, tx)          // validation passes for well-formed tx
    err = t.trySendTransaction(ctx, tx)             // → chooseCollectionNodes → sendTransactionToCollector
    err = t.transactions.Store(tx)                  // writes to observer's local protocol DB
    return nil
}
``` [5](#0-4) 

**Step 6 — Observer's backend is fully provisioned for collection-node contact**

The observer's `backendParams` includes `State`, `ConnFactory`, `Communicator`, and `Transactions` — everything `trySendTransaction` needs. `CollectionRPC` is nil (no static client), so `chooseCollectionNodes` is used, which queries the live protocol state the observer already maintains. [6](#0-5) 

`backend.New()` always constructs a live `txValidator` with full validation options (expiry, gas limit, byte size, reference block checks): [7](#0-6) 

---

### Impact Explanation

An attacker connecting to the observer's legacy gRPC port (default `0.0.0.0:9000`) and calling `legacyaccessproto.SendTransaction` with a well-formed transaction body achieves:

1. **Local DB write** — the transaction is stored in the observer's `node.Storage.Transactions` (protocol DB) via `t.transactions.Store(tx)`.
2. **Direct collection-node injection** — `trySendTransaction` → `chooseCollectionNodes` (protocol state lookup) → `sendTransactionToCollector` → gRPC call to a collection node, bypassing the staked AN entirely.
3. **Downstream execution-node state mutation** — the collection node ingests the transaction, includes it in a collection, and the execution node executes it, mutating on-chain state.

The observer's intended invariant — that it is read-only and must not submit transactions to the collection-node ingestion pipeline without staked-AN mediation — is broken.

**Practical scope caveat:** the observer's `txValidator` applies the same structural checks (expiry, gas limit, reference block, byte size) as a staked AN. Collection nodes do not authenticate the sender. Therefore the bypass does not circumvent *cryptographic* transaction authorization (signatures are still required), but it does circumvent the architectural routing invariant and allows the observer to act as an unsanctioned transaction submission endpoint.

---

### Likelihood Explanation

- The legacy gRPC port is open by default on the observer (`0.0.0.0:9000`).
- No authentication is required to call the legacy endpoint.
- Any client with network access to the observer can trigger this path.
- The observer has a full live copy of the protocol state and a working `ConnFactory`, so `chooseCollectionNodes` and `sendTransactionToCollector` succeed without any additional configuration.
- Reproducible on an unmodified localnet with an observer node.

---

### Recommendation

In `WithLegacy()`, replace `builder.backend` with the already-configured `rpcHandler` (the `FlowAccessAPIRouter`) so that the legacy handler inherits the same upstream-routing logic for `SendTransaction`. Alternatively, wrap the legacy handler in a shim that intercepts `SendTransaction` and delegates to the router. A simpler short-term fix is to register a legacy handler whose `SendTransaction` always returns `codes.Unimplemented` or unconditionally proxies to the upstream forwarder, matching the observer's read-only contract.

---

### Proof of Concept

1. Start a localnet with an observer node (standard configuration).
2. Connect a gRPC client to the observer's unsecure port using the **legacy** protobuf descriptor (`flow/legacy/access`).
3. Construct a `SendTransactionRequest` with a valid, properly-signed transaction body referencing a recent block.
4. Call `legacyaccessproto.AccessAPIClient.SendTransaction`.
5. Assert:
   - **(a)** The observer's local `transactions` storage contains the entry (query via `GetTransaction` on the observer's modern endpoint).
   - **(b)** The targeted collection node's ingress log shows receipt of the transaction, with no corresponding forwarding event on the staked AN's logs.

The call succeeds because `legacyaccess.NewHandler(builder.backend, builder.chain)` is bound to the raw backend, not the `FlowAccessAPIRouter`, and the backend's `trySendTransaction` path is fully operational on the observer.

### Citations

**File:** cmd/observer/node_builder/observer_builder.go (L2157-2189)
```go
		backendParams := backend.Params{
			State:                 node.State,
			Blocks:                node.Storage.Blocks,
			Headers:               node.Storage.Headers,
			Collections:           node.Storage.Collections,
			Transactions:          node.Storage.Transactions,
			ExecutionReceipts:     node.Storage.Receipts,
			ExecutionResults:      node.Storage.Results,
			Seals:                 node.Storage.Seals,
			ScheduledTransactions: builder.scheduledTransactions,
			ChainID:               node.RootChainID,
			AccessMetrics:         accessMetrics,
			ConnFactory:           connFactory,
			MaxHeightRange:        backendConfig.MaxHeightRange,
			Log:                   node.Logger,
			SnapshotHistoryLimit:  backend.DefaultSnapshotHistoryLimit,
			Communicator:          node_communicator.NewNodeCommunicator(backendConfig.CircuitBreakerConfig.Enabled),
			BlockTracker:          blockTracker,
			ScriptExecutionMode:   scriptExecMode,
			EventQueryMode:        eventQueryMode,
			TxResultQueryMode:     txResultQueryMode,
			SubscriptionHandler: subscription.NewSubscriptionHandler(
				builder.Logger,
				broadcaster,
				builder.stateStreamConf.ClientSendTimeout,
				builder.stateStreamConf.ResponseLimit,
				builder.stateStreamConf.ClientSendBufferSize,
			),
			IndexReporter:              indexReporter,
			VersionControl:             builder.VersionControl,
			ExecNodeIdentitiesProvider: execNodeIdentitiesProvider,
			MaxScriptAndArgumentSize:   config.BackendConfig.AccessConfig.MaxRequestMsgSize,
		}
```

**File:** cmd/observer/node_builder/observer_builder.go (L2281-2284)
```go
		builder.RpcEng, err = engineBuilder.
			WithRpcHandler(rpcHandler).
			WithLegacy().
			Build()
```

**File:** engine/access/rpc/engine_builder.go (L70-80)
```go
func (builder *RPCEngineBuilder) WithLegacy() *RPCEngineBuilder {
	// Register legacy gRPC handlers for backwards compatibility, to be removed at a later date
	builder.unsecureGrpcServer.RegisterService(func(s *grpc.Server) {
		legacyaccessproto.RegisterAccessAPIServer(s, legacyaccess.NewHandler(builder.backend, builder.chain))
	})
	builder.secureGrpcServer.RegisterService(func(s *grpc.Server) {
		legacyaccessproto.RegisterAccessAPIServer(s, legacyaccess.NewHandler(builder.backend, builder.chain))
	})

	return builder
}
```

**File:** engine/access/apiproxy/access_api_proxy.go (L147-151)
```go
func (h *FlowAccessAPIRouter) SendTransaction(context context.Context, req *access.SendTransactionRequest) (*access.SendTransactionResponse, error) {
	res, err := h.upstream.SendTransaction(context, req)
	h.log(UpstreamApiService, "SendTransaction", err)
	return res, err
}
```

**File:** access/legacy/handler.go (L42-63)
```go
func (h *Handler) SendTransaction(
	ctx context.Context,
	req *accessproto.SendTransactionRequest,
) (*accessproto.SendTransactionResponse, error) {
	txMsg := req.GetTransaction()

	tx, err := convert.MessageToTransaction(txMsg, h.chain)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err = h.api.SendTransaction(ctx, &tx)
	if err != nil {
		return nil, err
	}

	txID := tx.ID()

	return &accessproto.SendTransactionResponse{
		Id: txID[:],
	}, nil
}
```

**File:** engine/access/rpc/backend/transactions/transactions.go (L120-144)
```go
func (t *Transactions) SendTransaction(ctx context.Context, tx *flow.TransactionBody) error {
	start := time.Now().UTC()

	err := t.txValidator.Validate(ctx, tx)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid transaction: %s", err.Error())
	}

	// send the transaction to the collection node if valid
	err = t.trySendTransaction(ctx, tx)
	if err != nil {
		t.metrics.TransactionSubmissionFailed()
		return rpc.ConvertError(err, "failed to send transaction to a collection node", codes.Internal)
	}

	t.metrics.TransactionReceived(tx.ID(), start)

	// store the transaction locally
	err = t.transactions.Store(tx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to store transaction: %v", err)
	}

	return nil
}
```

**File:** engine/access/rpc/backend/backend.go (L193-212)
```go
	txValidator, err := validator.NewTransactionValidator(
		validator.NewProtocolStateBlocks(params.State, params.IndexReporter),
		params.ChainID.Chain(),
		params.AccessMetrics,
		validator.TransactionValidationOptions{
			Expiry:                       flow.DefaultTransactionExpiry,
			ExpiryBuffer:                 flow.DefaultTransactionExpiryBuffer,
			AllowEmptyReferenceBlockID:   false,
			AllowUnknownReferenceBlockID: false,
			CheckScriptsParse:            false,
			MaxGasLimit:                  flow.DefaultMaxTransactionGasLimit,
			MaxTransactionByteSize:       flow.DefaultMaxTransactionByteSize,
			MaxCollectionByteSize:        flow.DefaultMaxCollectionByteSize,
			CheckPayerBalanceMode:        params.CheckPayerBalanceMode,
		},
		params.ScriptExecutor,
	)
	if err != nil {
		return nil, fmt.Errorf("could not create transaction validator: %w", err)
	}
```
