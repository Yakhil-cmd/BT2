## Title
Unbounded ViewClientActor thread-pool exhaustion via repeated compute-heavy `CallFunction` view queries - ([File: chain/jsonrpc/src/api/query.rs, runtime/runtime/src/state_viewer/mod.rs])

## Summary
`TrieViewer::call_function` executes an attacker-deployed contract with a gas cap derived from `max_gas_burnt_view` (defaulting to the protocol's `max_gas_burnt` limit when not explicitly configured), and this execution runs synchronously inside a handler on `ViewClientActor`, which is a fixed-size multithreaded actor pool (`config.view_client_threads`, default small number of threads) shared by all RPC/view-client consumers on the node. An unprivileged attacker can deploy a contract containing a CPU-heavy loop that stays within the gas cap and repeatedly issue concurrent `CallFunction` RPC queries to occupy all `ViewClientActor` threads for the duration of gas-bounded-but-still-substantial wall-clock execution.

## Finding Description
`RpcQueryRequest`/`query()` in `chain/jsonrpc/src/api/query.rs` forwards `QueryRequest::CallFunction` as a `Query`/`ClientQuery` message to `ViewClientActor` [1](#0-0) . `ViewClientActor` is spawned as a multithread actor with a configurable but bounded thread count (`config.view_client_threads`) shared across all callers of the four handled message types (`Query`, `GetBlock`, `TxStatus`, etc.) [2](#0-1) [3](#0-2) , and documentation confirms it "runs in four threads by default but this number is configurable" [4](#0-3) .

The `Query` handler eventually dispatches to `TrieViewer::call_function`, which sets `gas: self.max_gas_burnt_view(...)` on the synthetic `FunctionCallAction` and builds a `ViewConfig { max_gas_burnt: max_gas_burnt_view }` before calling `execute_function_call` synchronously on the calling (ViewClientActor) thread [5](#0-4) . `max_gas_burnt_view` resolves to an explicit per-node override or, if unset, to the protocol's normal `max_gas_burnt` limit for the runtime config [6](#0-5) . This value is independent of the actual per-chunk `gas_limit` used for real transaction execution, and the ViewApplyState/ApplyState built for view calls sets `gas_limit: None` — there is no per-chunk aggregate bound applied to view calls at all, only the single-call `max_gas_burnt_view` cap [7](#0-6) .

Because gas metering bounds only the *amount of computation* per call, not wall-clock time, and this limit can be as large as the protocol's genesis/runtime `max_gas_burnt` (hundreds of Tgas) when the operator does not override `max_gas_burnt_view` to a lower value, a single call can occupy a ViewClientActor worker thread for a non-trivial amount of wall-clock time executing pure WASM computation (e.g., recursive fibonacci or a busy loop, as exercised by the existing `max_gas_burnt_view` tests) [8](#0-7) . No RPC-layer rate limiting, per-account/per-IP throttling, or admission control exists in `chain/jsonrpc` for `CallFunction`/`query` requests — the only throttling infrastructure found in the codebase (`state_request_throttle_period`, `state_requests_per_throttle_period`) applies to a different message type (state sync `StateRequestActor`), not to `Query`/`CallFunction`.

Thus an unprivileged account can: (1) deploy a contract with a CPU-heavy, gas-bounded loop via a normal `DeployContract` transaction; (2) issue many concurrent `CallFunction` queries against it via the public JSON-RPC `query` endpoint, each of which occupies one of the finite `ViewClientActor` worker threads for the duration of the gas-bounded WASM execution; (3) with enough concurrent requests (bounded only by the attacker's own request-issuing capacity, not by any server-side limit), saturate all `view_client_threads` workers, delaying or starving unrelated `Query`, `GetBlock`, `TxStatus`, and other ViewClientActor-handled RPC requests from legitimate users on that node.

## Impact Explanation
This is a node/RPC-availability (liveness) issue scoped to the affected node's `ViewClientActor` thread pool: while the pool is saturated by attacker-controlled CPU-bound WASM execution, other RPC consumers experience degraded or blocked view-related queries (`query`, `block`, `chunk`, `tx`, `validators`, etc., per the handler table) [9](#0-8) . It does not affect consensus, block production, or `ClientActor` (which runs separately) — chain progress and protocol invariants (balances, gas accounting, state divergence) are unaffected — so this maps to a bounded "unbounded resource use / node degradation" (NODE_PANIC_OR_UNBOUNDED_RESOURCE_USE) impact against the RPC/view-serving surface of a single node, not a full-network or protocol-level compromise.

## Likelihood Explanation
Feasibility is high and fully within the reach of an unprivileged attacker: deploying a contract and calling public RPC `query` methods requires no special privileges. The precondition that most strongly determines severity is the operator's `max_gas_burnt_view` setting — nodes that leave it unset inherit the full protocol `max_gas_burnt`, which permits gas-bounded computations that still take meaningful wall-clock time; nodes that explicitly lower `max_gas_burnt_view` (as documented and exercised by `tests/sanity/rpc_max_gas_burnt.py` and `test-loop-tests/src/tests/max_gas_burnt_view.rs`) mitigate but do not eliminate the exposure, since even a lower cap still permits some CPU-bound work per call, and there is no limit on the number of concurrent calls. Repeatability is trivial: the attacker can re-issue the same query indefinitely and in parallel.

## Recommendation
Add admission control for view/`CallFunction` queries independent of the existing single-call gas cap: e.g., a per-IP/per-account rate limiter or request queue with backpressure in `chain/jsonrpc`, a dedicated/isolated thread pool or priority lane for `CallFunction` versus lighter-weight view-client message types, and/or a wall-clock execution timeout enforced around `execute_function_call` in `TrieViewer::call_function` so a single slow view call cannot indefinitely occupy a worker thread. Additionally, consider lowering the effective default `max_gas_burnt_view` bound (documented operator-facing knob) and provide guidance/defaults that decouple it more conservatively from the protocol's chunk-level `max_gas_burnt`.

## Proof of Concept
Integration/load test plan (extending the pattern in `test-loop-tests/src/tests/max_gas_burnt_view.rs` and `integration-tests/src/tests/client/query_client.rs`):
1. Spin up a single node with default (or realistic) `view_client_threads` (e.g., 4) and default `max_gas_burnt_view`.
2. Deploy a contract exposing a method that performs a CPU-heavy loop bounded to consume close to `max_gas_burnt_view` gas (e.g., a large-N Fibonacci or busy-loop, per `fibonacci` test contract used in `test_max_gas_burnt_view`).
3. Concurrently issue `N > view_client_threads` `CallFunction` queries against this method via `ViewClientActor`'s `Query` handler (or JSON-RPC `query`), while simultaneously issuing a lightweight `ViewAccount`/`GetBlock` query from a separate "victim" client.
4. Assert: victim query latency exceeds an acceptable bound (e.g., stays queued until an attacker-occupied thread frees up), demonstrating that ViewClientActor's shared thread pool is starved by attacker-controlled CPU-bound view execution, and that no server-side rate limit or timeout intervenes.

### Citations

**File:** chain/jsonrpc/RPC_ARCHITECTURE.md (L122-135)
```markdown
| Method | Handler | Backend Actor |
|---|---|---|
| `block` | `block()` | ViewClientActor (GetBlock) |
| `broadcast_tx_async` | `send_tx_async()` | RpcHandlerActor (fire-and-forget) |
| `broadcast_tx_commit` | `send_tx_commit()` | RpcHandlerActor + ViewClientActor (submit, then poll) |
| `chunk` | `chunk()` | ViewClientActor (GetChunk) |
| `gas_price` | `gas_price()` | ViewClientActor (GetGasPrice) |
| `health` | `health()` | ClientActor (Status with is_health_check=true) |
| `network_info` | `network_info()` | ClientActor (GetNetworkInfo) |
| `send_tx` | `send_tx()` | RpcHandlerActor + ViewClientActor |
| `status` | `status()` | ClientActor (Status) |
| `tx` | `tx_status_common()` | ViewClientActor (TxStatus) |
| `validators` | `validators()` | ViewClientActor (GetValidatorInfo) |
| `query` | `query()` | ViewClientActor (ClientQuery) |
```

**File:** chain/jsonrpc/RPC_ARCHITECTURE.md (L155-164)
```markdown
### The Query Method

The `query` method has special routing (see Gotchas above). The flow:

1. Parse `RpcQueryRequest` (supports both legacy path and modern object format).
2. Determine the query sub-type for metrics (e.g., `query_view_account`).
3. Send `ClientQuery` to `ViewClientActor`.
4. Response goes through `process_query_response()` for backward-compatible error formatting.

Query types: `ViewAccount`, `ViewCode`, `ViewState`, `ViewAccessKey`, `ViewAccessKeyList`, `CallFunction`, `ViewGasKeyNonces`, `ViewGlobalContractCode`, `ViewGlobalContractCodeByAccountId`.
```

**File:** chain/client/src/view_client_actor.rs (L115-142)
```rust
impl ViewClientActor {
    pub fn spawn_multithread_actor(
        clock: Clock,
        actor_system: ActorSystem,
        chain_genesis: ChainGenesis,
        epoch_manager: Arc<dyn EpochManagerAdapter>,
        shard_tracker: ShardTracker,
        runtime: Arc<dyn RuntimeAdapter>,
        network_adapter: PeerManagerAdapter,
        config: ClientConfig,
        adv: crate::adversarial::Controls,
        validator_signer: MutableValidatorSigner,
    ) -> MultithreadRuntimeHandle<ViewClientActor> {
        actor_system.spawn_multithread_actor(config.view_client_threads, move || {
            ViewClientActor::new(
                clock.clone(),
                chain_genesis.clone(),
                epoch_manager.clone(),
                shard_tracker.clone(),
                runtime.clone(),
                network_adapter.clone(),
                config.clone(),
                adv.clone(),
                validator_signer.clone(),
            )
            .unwrap()
        })
    }
```

**File:** chain/client/src/view_client_actor.rs (L759-765)
```rust
impl Handler<Query, Result<QueryResponse, QueryError>> for ViewClientActor {
    fn handle(&mut self, msg: Query) -> Result<QueryResponse, QueryError> {
        tracing::debug!(target: "client", ?msg);
        let _timer = metrics::VIEW_CLIENT_MESSAGE_TIME.with_label_values(&["Query"]).start_timer();
        self.handle_query(msg)
    }
}
```

**File:** docs/architecture/how/README.md (L42-42)
```markdown
  `ViewClientActor` runs in four threads by default but this number is configurable.
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L346-368)
```rust
        let apply_state = ApplyState {
            apply_reason: ApplyChunkReason::ViewTrackedShard,
            block_height: view_state.block_height,
            // Used for legacy reasons
            prev_block_hash: view_state.prev_block_hash,
            shard_id: view_state.shard_id,
            epoch_id: view_state.epoch_id,
            epoch_height: view_state.epoch_height,
            gas_price: Balance::ZERO,
            block_timestamp: view_state.block_timestamp,
            gas_limit: None,
            random_seed: root,
            current_protocol_version: view_state.current_protocol_version,
            config: Arc::clone(config),
            next_wasm_config: None,
            cache: view_state.cache,
            is_new_chunk: false,
            save_receipt_to_tx: false,
            congestion_info: Default::default(),
            bandwidth_requests: BlockBandwidthRequests::empty(),
            trie_access_tracker_state: Default::default(),
            on_post_state_ready: None,
        };
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L369-435)
```rust
        let function_call = FunctionCallAction {
            method_name: method_name.to_string(),
            args: args.to_vec(),
            gas: self.max_gas_burnt_view(view_state.current_protocol_version),
            deposit: Balance::ZERO,
        };
        let action_receipt = ActionReceipt {
            signer_id: originator_id.clone(),
            signer_public_key: public_key,
            gas_price: Balance::ZERO,
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: vec![function_call.clone().into()],
        };
        let receipt = Receipt::V0(ReceiptV0 {
            predecessor_id: contract_id.clone(),
            receiver_id: contract_id.clone(),
            receipt_id: empty_hash,
            receipt: ReceiptEnum::Action(action_receipt.clone()),
        });
        let pipeline = ReceiptPreparationPipeline::new(
            Arc::clone(config),
            apply_state.next_wasm_config.clone(),
            apply_state.cache.as_ref().map(|v| v.handle()),
            state_update.contract_storage().clone(),
            epoch_info_provider.chain_id(),
            apply_state.shard_id,
        );
        let max_gas_burnt_view = self.max_gas_burnt_view(view_state.current_protocol_version);
        let view_config = Some(ViewConfig { max_gas_burnt: max_gas_burnt_view });
        let contract_id_resolved = RuntimeContractIdentifier::resolve(
            contract_id,
            account.contract().into_owned(),
            &state_update,
            &epoch_info_provider.chain_id(),
            AccessOptions::DEFAULT,
        )?;
        let contract =
            pipeline.get_contract(&receipt, contract_id_resolved, 0, view_config.clone());

        let mut runtime_ext = RuntimeExt::new(
            &mut state_update,
            &mut receipt_manager,
            contract_id.clone(),
            account,
            empty_hash,
            view_state.epoch_id,
            view_state.block_height,
            epoch_info_provider,
            view_state.current_protocol_version,
            config.wasm_config.storage_get_mode,
            Arc::clone(&apply_state.trie_access_tracker_state),
        );
        let outcome = execute_function_call(
            contract,
            &apply_state,
            &mut runtime_ext,
            originator_id,
            &VersionedActionReceipt::from(action_receipt),
            [].into(),
            &function_call,
            &empty_hash,
            config,
            true,
            view_config,
        )
        .map_err(|e| errors::CallFunctionError::InternalError { error_message: e.to_string() })?;
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L459-467)
```rust
    fn max_gas_burnt_view(&self, protocol_version: ProtocolVersion) -> Gas {
        self.max_gas_burnt_view.unwrap_or_else(|| {
            self.runtime_config_store
                .get_config(protocol_version)
                .wasm_config
                .limit_config
                .max_gas_burnt
        })
    }
```

**File:** test-loop-tests/src/tests/max_gas_burnt_view.rs (L38-54)
```rust
    // `fibonacci` takes a single byte argument and returns the result as
    // little-endian u64 bytes.
    let call_fib = |node_index: usize, n: u8| -> Result<QueryResponse, QueryError> {
        env.node(node_index).runtime_query(QueryRequest::CallFunction {
            account_id: contract_account.clone(),
            method_name: "fibonacci".to_owned(),
            args: vec![n].into(),
        })
    };
    let decode_result = |result: &[u8]| u64::from_le_bytes(result.try_into().unwrap());

    // Node 0 uses the default (high) limit: fibonacci(25) succeeds.
    let response = call_fib(0, 25).unwrap();
    let QueryResponseKind::CallResult(call_result) = response.kind else {
        panic!("expected CallResult")
    };
    assert_eq!(decode_result(&call_result.result), 75025);
```
