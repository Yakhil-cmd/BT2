### Title
Unbounded `account_ids` list in `StateChangesRequestView::AccountChanges` causes unmetered per-account RocksDB scans - ([File: chain/jsonrpc/src/api/changes.rs])

### Summary
`RpcStateChangesInBlockByTypeRequest::parse` simply delegates to `Params::parse(value)`, which deserializes `StateChangesRequestView` directly from JSON with no cap on the size of `account_ids: Vec<AccountId>`. Every account id in that list produces a separate RocksDB prefix scan in `ChainStore::get_state_changes`, so a request with a very large `account_ids` array causes proportionally large CPU/IO work on an RPC or view-client node.

### Finding Description
`RpcStateChangesInBlockByTypeRequest::parse` (`chain/jsonrpc/src/api/changes.rs:16-20`) calls `Params::parse(value)`, and `StateChangesRequestView::AccountChanges { account_ids }` (`core/primitives/src/views.rs:2741-2743`) is deserialized straight from the client-supplied JSON with no length validation anywhere in the parse path. The request flows to `ViewClientActor`'s `Handler<GetStateChanges, ...>` (`chain/client/src/view_client_actor.rs:994-1007`), which calls `ChainStore::get_state_changes` (`chain/chain/src/store/mod.rs:662-699`). For `AccountChanges`, that function iterates `account_ids` and, for every single id, builds a `KeyForStateChanges` and performs a `storage_key.find_exact_iter(&store)` RocksDB lookup [1](#0-0) . The same unbounded per-id loop pattern also applies to `SingleAccessKeyChanges`, `AllAccessKeyChanges`, `ContractCodeChanges`, and `DataChanges` [2](#0-1) . There is no cap on `account_ids.len()` in `RpcStateChangesInBlockByTypeRequest`/`StateChangesRequestView` [3](#0-2) [4](#0-3) , and `Handler<GetStateChanges, ...>` performs no size checking before dispatching to the store [5](#0-4) .

The only mitigating control found is a generic HTTP request body size limit (documented as 10MB by default) applied at the Axum middleware layer, unrelated to this specific field [6](#0-5) . A 10MB body can still encode on the order of hundreds of thousands of short valid `AccountId` strings (e.g. `"a.a"`-style JSON entries), which is enough to drive a large number of RocksDB scans, each with a distinct storage-engine seek/iterator setup cost, in a single synchronous handler call with no additional per-request cap, timeout-based abort, or pagination.

### Impact Explanation
This matches the "node panic or unbounded resource use" impact class: a single unauthenticated RPC request can force the `ViewClientActor` (and the underlying RocksDB store) to perform an amount of work proportional to attacker-chosen list size, well beyond what a normal client would send, degrading or blocking RPC service for other users (CPU/IO exhaustion, thread pool starvation on the view-client actor pool). It does not cause fund loss, consensus divergence, or gas/metering bypass since this is a read-only RPC path with no on-chain state effect — the impact is scoped to availability/DoS of the RPC/view node, not chain-level state integrity.

### Likelihood Explanation
The precondition is trivial: any unauthenticated caller with access to the public RPC endpoint (`changes` / `EXPERIMENTAL_changes` method) can submit this JSON, no signed transaction or privileged access required. It's fully repeatable and requires no timing, races, or leaked keys — a single crafted JSON POST is sufficient, bounded only by the generic HTTP body size limit (default 10MB), which is not tuned to bound this specific attack surface.

### Recommendation
Add an explicit maximum-size validation on `account_ids` (and similarly `keys` for `SingleAccessKeyChanges`) inside `RpcRequest::parse` for `RpcStateChangesInBlockByTypeRequest`, rejecting requests above a small configurable threshold (e.g. a few hundred) with a `RpcParseError`/`RpcStateChangesError` before dispatching to `ViewClientActor`. Alternatively/additionally, enforce the limit inside `ChainStore::get_state_changes` (or the `Handler<GetStateChanges, ...>` in `view_client_actor.rs`) and consider adding a scan-budget mechanism analogous to `receipt_to_tx_max_outcomes_per_request` already used elsewhere in the codebase for bounding unauthenticated public endpoint work [7](#0-6) .

### Proof of Concept
Integration test plan (to be added under `pytest/tests/sanity/` or as a Rust integration test similar to `test-loop-tests/src/tests/view_requests_to_archival_node.rs`):
1. Start a node with RPC enabled and a small set of real accounts/blocks (as in `pytest/tests/sanity/rpc_state_changes.py`).
2. Construct a `changes` JSON-RPC request with `"changes_type": "account_changes"` and an `account_ids` array containing e.g. 1,000,000 distinct fabricated `AccountId` strings (most non-existent, to isolate scan cost rather than payload size).
3. Measure server-side wall-clock time, CPU usage, and `ViewClientActor` thread occupancy while processing the single request, and compare growth against `account_ids.len()` (10, 1,000, 100,000, 1,000,000).
4. Assert expectation: the request either fails fast with a size-limit error (post-fix) or currently succeeds/hangs with processing time/CPU scaling roughly linearly with list size and no rejection (pre-fix), demonstrating the missing bound described in `ChainStore::get_state_changes` [1](#0-0) .

### Citations

**File:** chain/chain/src/store/mod.rs (L690-699)
```rust
            StateChangesRequest::AccountChanges { account_ids } => {
                let mut changes = StateChanges::new();
                for account_id in account_ids {
                    let data_key = TrieKey::Account { account_id: account_id.clone() };
                    let storage_key = KeyForStateChanges::from_trie_key(block_hash, &data_key);
                    let changes_per_key = storage_key.find_exact_iter(&store);
                    changes.extend(StateChanges::from_account_changes(changes_per_key));
                }
                changes
            }
```

**File:** chain/chain/src/store/mod.rs (L700-742)
```rust
            StateChangesRequest::SingleAccessKeyChanges { keys } => {
                let mut changes = StateChanges::new();
                for key in keys {
                    let data_key = TrieKey::access_key(key.account_id.clone(), &key.public_key);
                    let storage_key = KeyForStateChanges::from_trie_key(block_hash, &data_key);
                    let changes_per_key = storage_key.find_iter(&store);
                    changes.extend(StateChanges::from_access_key_changes(changes_per_key));
                }
                changes
            }
            StateChangesRequest::AllAccessKeyChanges { account_ids } => {
                let mut changes = StateChanges::new();
                for account_id in account_ids {
                    let data_key = trie_key_parsers::get_raw_prefix_for_access_keys(account_id);
                    let storage_key = KeyForStateChanges::from_raw_key(block_hash, &data_key);
                    let changes_per_key_prefix = storage_key.find_iter(&store);
                    changes.extend(StateChanges::from_access_key_changes(changes_per_key_prefix));
                }
                changes
            }
            StateChangesRequest::ContractCodeChanges { account_ids } => {
                let mut changes = StateChanges::new();
                for account_id in account_ids {
                    let data_key = TrieKey::ContractCode { account_id: account_id.clone() };
                    let storage_key = KeyForStateChanges::from_trie_key(block_hash, &data_key);
                    let changes_per_key = storage_key.find_exact_iter(&store);
                    changes.extend(StateChanges::from_contract_code_changes(changes_per_key));
                }
                changes
            }
            StateChangesRequest::DataChanges { account_ids, key_prefix } => {
                let mut changes = StateChanges::new();
                for account_id in account_ids {
                    let data_key = trie_key_parsers::get_raw_prefix_for_contract_data(
                        account_id,
                        key_prefix.as_ref(),
                    );
                    let storage_key = KeyForStateChanges::from_raw_key(block_hash, &data_key);
                    let changes_per_key_prefix = storage_key.find_iter(&store);
                    changes.extend(StateChanges::from_data_changes(changes_per_key_prefix));
                }
                changes
            }
```

**File:** chain/jsonrpc-primitives/src/types/changes.rs (L17-22)
```rust
pub struct RpcStateChangesInBlockByTypeRequest {
    #[serde(flatten)]
    pub block_reference: near_primitives::types::BlockReference,
    #[serde(flatten)]
    pub state_changes_request: near_primitives::views::StateChangesRequestView,
}
```

**File:** core/primitives/src/views.rs (L2740-2758)
```rust
pub enum StateChangesRequestView {
    AccountChanges {
        account_ids: Vec<AccountId>,
    },
    SingleAccessKeyChanges {
        keys: Vec<AccountWithPublicKey>,
    },
    AllAccessKeyChanges {
        account_ids: Vec<AccountId>,
    },
    ContractCodeChanges {
        account_ids: Vec<AccountId>,
    },
    DataChanges {
        account_ids: Vec<AccountId>,
        #[serde(rename = "key_prefix_base64")]
        key_prefix: StoreKey,
    },
}
```

**File:** chain/client/src/view_client_actor.rs (L994-1007)
```rust
impl Handler<GetStateChanges, Result<StateChangesView, GetStateChangesError>> for ViewClientActor {
    fn handle(&mut self, msg: GetStateChanges) -> Result<StateChangesView, GetStateChangesError> {
        tracing::debug!(target: "client", ?msg);
        let _timer =
            metrics::VIEW_CLIENT_MESSAGE_TIME.with_label_values(&["GetStateChanges"]).start_timer();
        Ok(self
            .chain
            .chain_store()
            .get_state_changes(&msg.block_hash, &msg.state_changes_request.into())
            .into_iter()
            .map(Into::into)
            .collect())
    }
}
```

**File:** chain/jsonrpc/RPC_ARCHITECTURE.md (L93-95)
```markdown
When `enable_debug_rpc` is true, additional routes under `/debug` and `/debug/api/` are registered.

Middleware: CORS (configurable via `cors_allowed_origins`) and request body size limit (default 10MB).
```

**File:** core/chain-configs/src/client_config.rs (L741-746)
```rust
    /// worst case on unauthenticated public endpoint. Default 20_000.
    /// Operators serving cold archival traffic with deep walks or sparse
    /// outcomes may raise; benchmark first (see TODO in
    /// `view_client_actor.rs`). Mid-scan exhaustion fails with
    /// `BudgetExceeded { scanned, limit }`.
    pub receipt_to_tx_max_outcomes_per_request: u64,
```
