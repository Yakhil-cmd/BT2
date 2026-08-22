Found a solid analog: `TrieViewer::view_access_keys` (used by the `ViewAccessKeyList` RPC query) iterates over *all* access keys of an account with no page/size limit, unlike `view_state`, which was explicitly hardened with pagination and per-page byte/item caps to solve exactly this "unbounded external work triggered by attacker-grown state" bug class.

### Title
Unbounded iteration over all access keys in `view_access_keys`/`ViewAccessKeyList` RPC query, unlike the paginated `view_state` - ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_access_keys`, which backs the `ViewAccessKeyList` RPC query type, iterates through every access key (and skips gas-key nonces) stored under an account's access-key trie prefix and collects them all into a single `Vec` with no limit on count or serialized size. This is structurally the same bug class as the Sherlock finding: an attacker-controlled, ever-growing collection is walked in full on every unprivileged read request, with no pagination, so the cost of a single request scales linearly with attacker-added state.

### Finding Description
`view_access_keys` builds the full list of access keys for an account by iterating the trie prefix for that account with no bound: [1](#0-0) 

This is reached from the `ViewAccessKeyList` query type in the runtime query dispatcher: [2](#0-1) 

and exposed directly as an unprivileged JSON-RPC endpoint that any caller can invoke for any account: [3](#0-2) 

By contrast, `view_state` (queries account contract-data trie entries, a structurally identical unbounded-collection risk) was explicitly fixed with `after_key`/`limit` pagination plus hard server-side caps (`MAX_VIEW_STATE_PAGE_ITEMS`, `MAX_VIEW_STATE_PAGE_BYTES`) so a single call can't be forced to walk or serialize unbounded state: [4](#0-3) 

`view_access_keys` has no equivalent per-page item/byte cap and no `limit`/`after_key` parameters at all — every call walks the entire access-key set for the account and returns it in one response. Anyone can grow this set arbitrarily on their own account by repeatedly submitting `AddKey` actions (each backed by storage staking, but that only limits how much an attacker must pay, not how large the account's key set — and hence the per-query workload for any observer — can become).

### Impact Explanation
An account can be inflated with a very large number of access keys (or gas keys, which are also enumerated and filtered per-key), and any subsequent `ViewAccessKeyList`/`view_access_key_list` RPC query against that account forces the serving RPC/view-client node to walk and serialize the entire key set in one synchronous call, with no limit on iteration count or response size. Because there's no per-page cap analogous to `MAX_VIEW_STATE_PAGE_ITEMS`/`MAX_VIEW_STATE_PAGE_BYTES`, this is unbounded resource use (CPU, memory, and response size) on a node servicing what should be a cheap, unprivileged read — a denial-of-information/DoS risk for that query path, growing with attacker-controlled state and never rejected or paginated, unlike the deliberately-fixed `view_state` path.

### Likelihood Explanation
Likelihood is moderate: creating many access keys costs storage stake (`Balance`), so the attack has a monetary cost proportional to the number of keys added, but no protocol-level cap prevents an account from accumulating enough keys (thousands to tens of thousands) to make `ViewAccessKeyList` calls against it expensive, and the query is reachable by any unprivileged caller against any account without needing the account owner's cooperation.

### Recommendation
Add pagination (e.g. `after_key`/`limit`) and server-side item/byte caps to `view_access_keys`/`ViewAccessKeyList`, mirroring the fix already applied to `view_state` (`MAX_VIEW_STATE_PAGE_ITEMS`/`MAX_VIEW_STATE_PAGE_BYTES`, `after_key`, `limit`), so a single request cannot be forced to enumerate or serialize an unbounded number of access keys.

### Proof of Concept
1. Create an account and repeatedly submit `AddKey` actions (paying the storage stake per key) until the account holds a very large number of access keys.
2. Issue a `ViewAccessKeyList` (or `EXPERIMENTAL`/`query` equivalent) RPC request for that account against any RPC/view-client node.
3. Observe that `view_access_keys` at [1](#0-0)  iterates and materializes the entire key set with no limit, unlike the capped iteration in `view_state` at [4](#0-3) , causing disproportionate CPU/memory/response-size cost per request as the key count grows.

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

**File:** runtime/runtime/src/state_viewer/mod.rs (L280-320)
```rust
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
