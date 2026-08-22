### Title
Unbounded `EXPERIMENTAL_view_access_key_list` cost scales with total gas-key nonces, not key count - ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_access_keys` iterates the entire trie prefix for an account's access keys and, for every raw key, calls `parse_key_handle_from_access_key_key` and `parse_nonce_index_from_gas_key_key` before discarding gas-key nonce sub-entries via `.filter_map_ok`. Since `GasKeyNonce` trie entries live directly under the `AccessKey` prefix [1](#0-0) , an account with many gas keys, each holding many nonce sub-entries, forces this free view RPC to do work proportional to the total number of nonces rather than the number of logical keys.

### Finding Description
`view_access_keys` iterates `state_update.iter(&prefix)` over the raw `AccessKey` trie prefix for the account and, per raw key, parses the key handle and then calls `parse_nonce_index_from_gas_key_key` to detect (and skip) `GasKeyNonce` entries: [2](#0-1) . Gas key nonces are stored as separate trie entries keyed by `TrieKey::GasKeyNonce { account_id, key_handle, index }`, which extends the corresponding `AccessKey` trie key with a `NonceIndex` suffix and therefore falls under the same raw prefix used by `get_raw_prefix_for_access_keys` [1](#0-0) [3](#0-2) .

Each gas key can have up to `AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY` nonce entries, enforced only at `AddKey` action-validation time [4](#0-3) . That check bounds nonces *per gas key* but places no bound on the number of gas keys an account may hold, nor on the total nonce count across all gas keys — that is limited only by how much storage stake the attacker is willing to lock up. An attacker can therefore add `K` gas keys, each with the maximum `N` nonces, making the account's `AccessKey` trie subtree contain `K*(1+N)` entries.

`EXPERIMENTAL_view_access_key_list` maps directly to `QueryRequest::ViewAccessKeyList`, which is routed through `NightshadeRuntime::view_access_keys` to `TrieViewer::view_access_keys` with no pagination, item limit, or gas/compute charge [5](#0-4) [6](#0-5) . Unlike `ViewState`, which supports `after_key`/`limit` pagination, `ViewAccessKeyList` has no such mechanism, so every call re-walks the full `K*(1+N)`-sized trie subtree, parsing and discarding all `K*N` nonce entries via `filter_map_ok`.

The RPC dispatch layer (`chain/jsonrpc/src/lib.rs`) treats `query` as a normal, unmetered read; there is no `max_gas_burnt_view`-style limit applied to trie-iteration view queries (that mechanism, seen in `test-loop-tests/src/tests/max_gas_burnt_view.rs`, only governs VM-executed `CallFunction`, not direct state queries like `ViewAccessKeyList`) [7](#0-6) .

### Impact Explanation
This is a compute-exhaustion amplification: for a fixed one-time storage-stake cost, an attacker can make each subsequent free RPC call scale with `K*N` trie reads/parses instead of `K`, and can repeat the query indefinitely for free. This matches the "unbounded resource use from unpriced RPC operations" / node compute exhaustion class rather than a fund-loss or consensus-divergence bug — it affects only the view/RPC-serving path and any validator or RPC node that serves this query, not chain state or consensus itself.

### Likelihood Explanation
Feasibility depends on how expensive it is in practice for an attacker to accumulate a very large `K*N` (bounded by `MAX_NONCES_FOR_GAS_KEY` per key and by however much NEAR the attacker locks in storage stake for many `AddKey` gas-key actions). Since gas keys were only just introduced (`ProtocolFeature::GasKeys`) and there is no cap on total account access keys other than storage cost, the attack is straightforward to set up: submit ordinary `AddKey` transactions from an unprivileged account, no special privileges required. The main uncertainty (not fully verified due to tool-call limits) is the exact numeric value of `MAX_NONCES_FOR_GAS_KEY` and whether any global "max access keys per account" limit exists elsewhere in `LimitConfig` that would cap `K` — searches for such a limit found no matches, suggesting no such cap exists, but this could not be fully confirmed.

### Recommendation
Add pagination/limit support to `ViewAccessKeyList` (mirroring `ViewState`'s `after_key`/`limit`), or make `view_access_keys` iterate only over key-handle boundaries (skipping the nonce-index sub-range directly via seek/prefix-skip rather than visiting and parsing every nonce entry), and/or apply a per-query iteration cap (e.g., reuse `max_gas_burnt_view`-style limits) to all trie-iterating view queries, not just VM `CallFunction`.

### Proof of Concept
Integration test plan:
1. Create an account and add `K` gas keys (e.g., K=200) via `AddKeyAction` with `AccessKey::gas_key_full_access(N)` where `N = MAX_NONCES_FOR_GAS_KEY`, paying the required storage stake.
2. Call `EXPERIMENTAL_view_access_key_list` (or `TrieViewer::view_access_keys` directly in a benchmark) and measure wall-time/trie-node-touch count.
3. Repeat with `K` gas keys each with `N=1` nonce, keeping `K*N` roughly constant, and compare cost.
4. Assert that cost is proportional to `K*N` rather than `K`, demonstrating that per-call cost scales with total nonces; flag absence of any cap/pagination enforcing `O(K)` behavior in `view_access_keys` (`runtime/runtime/src/state_viewer/mod.rs:150-192`).

### Citations

**File:** core/primitives/src/trie_key.rs (L294-302)
```rust
    /// Represents a single nonce for a gas key. Stored under `col::ACCESS_KEY`
    /// with a special key format: If an access key is used as a gas key, the
    /// keys used to store its nonces extend the access key trie key with a
    /// `NonceIndex` suffix.
    GasKeyNonce {
        account_id: AccountId,
        key_handle: PublicKeyHandle,
        index: NonceIndex,
    } = 21,
```

**File:** core/primitives/src/trie_key.rs (L550-556)
```rust
            TrieKey::GasKeyNonce { account_id, key_handle, index: nonce_index } => {
                buf.push(col::ACCESS_KEY);
                buf.extend(account_id.as_bytes());
                buf.push(ACCESS_KEY_SEPARATOR);
                append_key_handle_trie_id(buf, key_handle);
                buf.extend(&nonce_index.to_le_bytes());
            }
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L150-192)
```rust
    pub fn view_access_keys(
        &self,
        state_update: &TrieUpdate,
        account_id: &AccountId,
    ) -> Result<Vec<(PublicKeyHandle, AccessKey)>, errors::ViewAccessKeyError> {
        let prefix = trie_key_parsers::get_raw_prefix_for_access_keys(account_id);
        let access_keys =
            state_update
                .iter(&prefix)?
                .map(|key| {
                    let key = key?;
                    let key_handle = parse_key_handle_from_access_key_key(&key, account_id)
                        .map_err(|_| errors::ViewAccessKeyError::InternalError {
                            error_message: "Unexpected invalid access key from iterator"
                                .to_string(),
                        })?;
                    if let Some(_index) =
                        parse_nonce_index_from_gas_key_key(&key, account_id, &key_handle).map_err(
                            |_| errors::ViewAccessKeyError::InternalError {
                                error_message: "could not parse nonce index".to_string(),
                            },
                        )?
                    {
                        // This is a gas key nonce, skip it.
                        return Ok(None);
                    }
                    let access_key = near_store::get_access_key_by_handle(
                        state_update,
                        account_id,
                        &key_handle,
                    )?
                    .ok_or_else(|| {
                        near_primitives::errors::StorageError::StorageInconsistentState(format!(
                            "iterator yielded an access-key trie key with no value: {key_handle}"
                        ))
                    })?;

                    Ok(Some((key_handle, access_key)))
                })
                .filter_map_ok(|x| x)
                .collect::<Result<Vec<_>, errors::ViewAccessKeyError>>();
        access_keys
    }
```

**File:** runtime/runtime/src/action_validation.rs (L312-319)
```rust
        if gas_key_info.num_nonces == 0
            || gas_key_info.num_nonces > AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY
        {
            return Err(ActionsValidationError::GasKeyInvalidNumNonces {
                requested_nonces: gas_key_info.num_nonces,
                limit: AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY,
            });
        }
```

**File:** chain/chain/src/runtime/mod.rs (L1379-1400)
```rust
            QueryRequest::ViewAccessKeyList { account_id } => {
                let access_key_list =
                    self.view_access_keys(&shard_uid, *state_root, account_id).map_err(|err| {
                        crate::near_chain_primitives::error::QueryError::from_view_access_key_error(
                            err,
                            block_height,
                            *block_hash,
                        )
                    })?;
                Ok(QueryResponse {
                    kind: QueryResponseKind::AccessKeyList(
                        access_key_list
                            .into_iter()
                            .map(|(public_key, access_key)| {
                                AccessKeyInfoView::new(public_key, access_key.into())
                            })
                            .collect(),
                    ),
                    block_height,
                    block_hash: *block_hash,
                })
            }
```

**File:** runtime/runtime/src/adapter.rs (L56-61)
```rust
    fn view_access_keys(
        &self,
        shard_uid: &ShardUId,
        state_root: MerkleHash,
        account_id: &AccountId,
    ) -> Result<Vec<(PublicKeyHandle, AccessKey)>, crate::state_viewer::errors::ViewAccessKeyError>;
```

**File:** chain/jsonrpc/src/lib.rs (L1736-1761)
```rust
    async fn view_access_key_list_local(
        &self,
        request_data: RpcViewAccessKeyListRequest,
    ) -> Result<RpcViewAccessKeyListResponse, RpcViewAccessKeyListError> {
        let result = self
            .view_client_send(ClientQuery::new(
                request_data.block_reference,
                QueryRequest::ViewAccessKeyList { account_id: request_data.account_id },
            ))
            .await;
        let query_response: QueryResponse =
            result.map_err(<RpcQueryError as Into<RpcViewAccessKeyListError>>::into)?;
        match query_response.kind {
            near_primitives::views::QueryResponseKind::AccessKeyList(access_key_list) => {
                Ok(RpcViewAccessKeyListResponse {
                    access_key_list,
                    block_height: query_response.block_height,
                    block_hash: query_response.block_hash,
                })
            }
            _ => Err(RpcQueryError::InternalError {
                error_message: format!("Unexpected response kind from near client. Expected: AccessKeyList, found: {:?}", query_response.kind),
            }
            .into()),
        }
    }
```
