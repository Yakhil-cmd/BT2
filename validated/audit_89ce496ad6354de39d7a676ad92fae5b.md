### Title
Unbounded iteration in `TrieViewer::view_access_keys` allows resource-exhaustion DoS via `ViewAccessKeyList`/`EXPERIMENTAL_view_access_key_list` RPC queries - (File: `runtime/runtime/src/state_viewer/mod.rs`)

### Summary
`BondAggregator.liveMarketsBy` reverted because it looped over an ever-growing, unbounded on-chain data set inside a "view" call without any size/pagination cap, eventually exceeding the gas budget available to view calls. nearcore has the structurally identical pattern in `TrieViewer::view_access_keys`, which is used to serve the `ViewAccessKeyList` / `EXPERIMENTAL_view_access_key_list` RPC/query endpoints: it iterates the full access-key trie prefix for an account with no item cap, byte cap, or pagination, unlike the sibling `view_state` function which was hardened with exactly these protections.

### Finding Description
`view_access_keys` walks the whole access-key prefix for an account via `state_update.iter(&prefix)` and collects every entry into a `Vec` before returning: [1](#0-0) 

This is invoked directly from the `QueryRequest::ViewAccessKeyList` handler in the runtime query dispatcher with no additional bound: [2](#0-1) 

and is reachable by any unprivileged client through the public JSON-RPC `query`/`EXPERIMENTAL_view_access_key_list` endpoints: [3](#0-2) [4](#0-3) 

By contrast, the sibling `view_state` function (serving `ViewState`/`EXPERIMENTAL_view_state`) was explicitly hardened against exactly this class of bug: it enforces an `AccountStateTooLarge` legacy gate, and for paginated calls a hard per-page item cap (`MAX_VIEW_STATE_PAGE_ITEMS = 10_000`) and byte cap (`MAX_VIEW_STATE_PAGE_BYTES = 50_000`): [5](#0-4) 

No analogous `state_size_limit`, item cap, or pagination mechanism exists for `view_access_keys`. I found no protocol-level cap on the number of access keys (`AddKey` actions) a single account can accumulate (searches for `max_number_of_access_keys` returned no results); the only economic disincentive is the storage-staking cost per key, which is small and, given sufficient balance, allows an account to accumulate an arbitrarily large number of access keys.

### Impact Explanation
An attacker who funds a single account with enough NEAR to cover storage staking can add a very large number of access keys to it via ordinary `AddKey` transactions (no privileged role required). Any subsequent `view_access_key_list` / `EXPERIMENTAL_view_access_key_list` query against that account forces the view/RPC layer to fully materialize and serialize the unbounded key set with no cap, unlike the protected `view_state` path. This causes unbounded CPU/memory/response-size consumption on any RPC node serving that query, which is the "unbounded resource use" impact class explicitly accepted by this analysis's validation criteria. It is a node-level resource-exhaustion issue on public-facing RPC infrastructure rather than a consensus-breaking bug, and severity is lower than the original Solidity finding because growth here is attacker-funded and per-account rather than driven by ordinary global protocol usage, and there is no external-call-per-iteration cost multiplier — but the missing size/pagination guard is a real, unaddressed structural gap relative to the parallel fix already applied to `view_state`.

### Likelihood Explanation
Reachable by any unprivileged account: creating many access keys only requires paying the storage cost, and querying another account's access key list requires no authorization at all. Likelihood is moderate — it requires deliberate funding to accumulate a large key count, but no protocol permission, validator role, or special access, and the query itself is trivially triggerable by any RPC client.

### Recommendation
Apply the same protections already used for `view_state` to `view_access_keys` (and any similarly unbounded per-account trie-prefix iteration): 
- add a configurable `state_size_limit`-style check/`AccountStateTooLarge`-style rejection for the access-key list, and/or 
- add `after_key`/`limit`-style pagination with a hard per-page item cap analogous to `MAX_VIEW_STATE_PAGE_ITEMS`, mirroring the fix already implemented for `view_state`.

### Proof of Concept
1. Fund an account with enough balance to cover storage staking for a very large number of access keys.
2. Submit many `AddKey` transactions (or a large batch of `AddKey` actions per transaction/batch) to that account until it holds a very large number of access keys (bounded only by the account's storage balance, not by any protocol-level key-count cap).
3. Issue an `EXPERIMENTAL_view_access_key_list` (or `query` with `ViewAccessKeyList`) RPC request against that account.
4. Observe that `TrieViewer::view_access_keys` (`runtime/runtime/src/state_viewer/mod.rs:150-192`) iterates and materializes the entire key set with no item/byte cap or pagination, unlike `view_state`, causing disproportionate CPU/memory/response-size cost on the serving RPC node for a single unauthenticated query.

### Citations

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

**File:** runtime/runtime/src/state_viewer/mod.rs (L224-320)
```rust
    pub fn view_state(
        &self,
        state_update: &TrieUpdate,
        account_id: &AccountId,
        prefix: &[u8],
        after_key: Option<&[u8]>,
        limit: Option<NonZeroU32>,
        include_proof: bool,
    ) -> Result<ViewStateResult, errors::ViewStateError> {
        let paginated = limit.is_some() || after_key.is_some();
        if paginated && include_proof {
            return Err(errors::ViewStateError::ProofUnsupportedWithPagination);
        }
        if let Some(after_key) = after_key {
            if !after_key.starts_with(prefix) {
                return Err(errors::ViewStateError::AfterKeyOutsidePrefix);
            }
        }

        let Some(account) = get_account(state_update, account_id)? else {
            return Err(errors::ViewStateError::AccountDoesNotExist {
                requested_account_id: account_id.clone(),
            });
        };

        // Legacy per-account gate — paginated callers opt out of it.
        if !paginated {
            let code_len = state_update
                .get_code_len(
                    account_id.clone(),
                    account.local_contract_hash().unwrap_or_default(),
                )?
                .unwrap_or_default() as u64;
            if let Some(limit) = self.state_size_limit {
                if account.storage_usage().saturating_sub(code_len) > limit {
                    return Err(errors::ViewStateError::AccountStateTooLarge {
                        requested_account_id: account_id.clone(),
                    });
                }
            }
        }

        let query = trie_key_parsers::get_raw_prefix_for_contract_data(account_id, prefix);
        let acc_sep_len = query.len() - prefix.len();
        let mut iter = state_update.trie().disk_iter()?;
        iter.remember_visited_nodes(include_proof);

        match after_key {
            None => iter.seek_prefix(&query)?,
            Some(after_key) => {
                let mut full = query[..acc_sep_len].to_vec();
                full.extend_from_slice(after_key);
                iter.seek(Bound::Excluded(full))?;
            }
        }

        // Per-page caps, separate from the `trie_viewer_state_size_limit` that pagination skips.
        // The byte cap is soft: it's checked before each append, so a page can run one item over.
        const MAX_VIEW_STATE_PAGE_ITEMS: u32 = 10_000;
        const MAX_VIEW_STATE_PAGE_BYTES: u64 = 50_000;

        let (item_cap, byte_cap) = if paginated {
            let items = limit
                .map_or(MAX_VIEW_STATE_PAGE_ITEMS, NonZeroU32::get)
                .min(MAX_VIEW_STATE_PAGE_ITEMS);
            (Some(items), Some(MAX_VIEW_STATE_PAGE_BYTES))
        } else {
            (None, None)
        };

        // Pre-allocate only for an explicit `limit`; the default page size is too big to assume.
        let mut values = match (limit, item_cap) {
            (Some(_), Some(cap)) => Vec::with_capacity(cap as usize),
            _ => Vec::new(),
        };
        let mut used_bytes: u64 = 0;
        let mut last_key = None;

        for item in &mut iter {
            let (key, value) = item?;
            // `seek` (resumed pages) is not prefix-bounded — stop at the account edge.
            if !key.starts_with(&query) {
                break;
            }
            let hit_items = item_cap.is_some_and(|cap| values.len() as u64 >= u64::from(cap));
            let hit_bytes = byte_cap.is_some_and(|cap| used_bytes >= cap);
            if hit_items || hit_bytes {
                // At least one more item exists; resume after the last we kept.
                last_key = values.last().map(|it: &StateItem| it.key.clone());
                break;
            }
            used_bytes += (key.len() + value.len()) as u64;
            values.push(StateItem { key: key[acc_sep_len..].to_vec().into(), value: value.into() });
        }
        let proof = iter.into_visited_nodes();
        Ok(ViewStateResult { values, proof, last_key })
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

**File:** chain/jsonrpc/src/lib.rs (L1385-1399)
```rust
    async fn view_access_key_list_sharded(
        &self,
        request_data: RpcViewAccessKeyListRequest,
    ) -> Result<Value, RpcError> {
        let block_hint = request_data.block_reference.clone().into();
        let shard_hint = ShardHint::Account(request_data.account_id.clone());
        self.run_coordinator_request(
            "EXPERIMENTAL_view_access_key_list",
            request_data,
            block_hint,
            shard_hint,
            CoordinatorRequestStrategy::Sequential,
        )
        .await
    }
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
