### Title
Unbounded `account_ids`/`keys` arrays in `StateChangesRequestView` allow RPC-triggered resource exhaustion - ([File: chain/chain/src/store/mod.rs])

### Summary
The `changes` / `EXPERIMENTAL_changes` JSON-RPC methods accept a `StateChangesRequestView` whose `account_ids` and `keys` fields are plain `Vec<AccountId>` / `Vec<AccountWithPublicKey>` with no size limit enforced during deserialization or before processing, mirroring the reported eth/filters `FilterCriteria.topics` issue where an unbounded list is accepted and only iterated over later at high cost.

### Finding Description
`StateChangesRequestView` is defined with unconstrained vectors: [1](#0-0) 

It is deserialized directly from client-supplied JSON via the generic `Params::unwrap_or_parse`/`RpcRequest::parse` path, with no length cap applied: [2](#0-1) 

Once parsed, the vectors are consumed as-is. `extract_target_shards` maps every account/key to a shard with no cap: [3](#0-2) 

And `ChainStore::get_state_changes` performs a separate RocksDB prefix scan (`find_iter`/`find_exact_iter`) per entry in the (unbounded) list: [4](#0-3) 

The only server-side constraint is the generic HTTP body size cap (10MB), noted in the architecture doc, which is far too coarse to bound the number of distinct account/key entries an attacker can pack into a single request: [5](#0-4) 

Because `AccountId`s can be as short as 2 characters, tens of thousands of entries can fit well within the 10MB body limit, each triggering an independent store scan.

### Impact Explanation
An unprivileged client can submit a single `changes`/`EXPERIMENTAL_changes` RPC request with a very large `account_ids` or `keys` array. Each element causes an independent RocksDB range scan on the node handling the request (and, in sharded RPC setups, is fanned out via the scatter-gather coordinator to per-shard nodes), consuming CPU/I/O disproportionate to the request size and degrading or stalling RPC service for legitimate users. This matches the report's impact class of node/service resource exhaustion, without giving any real utility (unlike a well-formed changes query), i.e., unbounded resource use triggered by an unprivileged RPC call.

### Likelihood Explanation
Likelihood is high: the method is a standard, unauthenticated JSON-RPC endpoint, requires no special role or prior state, and the only guard is the generic body-size limit, which does not bound array cardinality for small account IDs.

### Recommendation
Enforce an explicit maximum number of entries (e.g., a small constant like 100) for `account_ids` and `keys` in `StateChangesRequestView` at parse time — analogous to validating topic count for `FilterCriteria` before use — returning a client error (400-equivalent `RpcError`) when the limit is exceeded, before any shard-layout mapping or store scanning occurs in `chain/jsonrpc/src/lib.rs` and `chain/chain/src/store/mod.rs`.

### Proof of Concept
Send a `changes` RPC request with a large synthetic `account_ids` list, e.g.:
```json
{"jsonrpc":"2.0","id":"1","method":"changes","params":{
  "block_id": "<valid_block_hash>",
  "changes_type": "account_changes",
  "account_ids": ["a0","a1","a2", ... /* tens of thousands of short ids */]
}}
```
Because each `AccountId` need only be 2+ characters, a request within the 10MB body cap can contain a very large number of entries, each driving a separate `find_exact_iter` store scan in `get_state_changes` [6](#0-5) , with no rejection at parse time.

### Citations

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

**File:** chain/jsonrpc/src/api/mod.rs (L150-165)
```rust
        pub fn parse(value: Value) -> Result<T, RpcParseError>
        where
            T: DeserializeOwned,
        {
            serde_json::from_value(value)
                .map_err(|e| RpcParseError(format!("Failed parsing args: {e}")))
        }

        /// If value hasn’t been parsed yet, tries to deserialize it directly
        /// into `T`.
        pub fn unwrap_or_parse(self) -> Result<T, RpcParseError>
        where
            T: DeserializeOwned,
        {
            self.0.unwrap_or_else(Self::parse)
        }
```

**File:** chain/jsonrpc/src/lib.rs (L285-302)
```rust
fn extract_target_shards(
    request: &StateChangesRequestView,
    shard_layout: &ShardLayout,
) -> HashSet<ShardId> {
    let account_ids: &[AccountId] = match request {
        StateChangesRequestView::AccountChanges { account_ids } => account_ids,
        StateChangesRequestView::SingleAccessKeyChanges { keys } => {
            return keys
                .iter()
                .map(|k| shard_layout.account_id_to_shard_id(&k.account_id))
                .collect();
        }
        StateChangesRequestView::AllAccessKeyChanges { account_ids } => account_ids,
        StateChangesRequestView::ContractCodeChanges { account_ids } => account_ids,
        StateChangesRequestView::DataChanges { account_ids, .. } => account_ids,
    };
    account_ids.iter().map(|id| shard_layout.account_id_to_shard_id(id)).collect()
}
```

**File:** chain/chain/src/store/mod.rs (L690-742)
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

**File:** chain/jsonrpc/RPC_ARCHITECTURE.md (L93-96)
```markdown
When `enable_debug_rpc` is true, additional routes under `/debug` and `/debug/api/` are registered.

Middleware: CORS (configurable via `cors_allowed_origins`) and request body size limit (default 10MB).

```
