## Title
Unbounded trie iteration over all access keys in `view_access_keys` allows an unprivileged account to DoS RPC/view nodes via the `ViewAccessKeyList` query — ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_access_keys`, which serves the `ViewAccessKeyList` RPC query (and is reused by the Rosetta adapter and the `mirror` tool), iterates over **every** access key trie entry for an account and collects them all into a single unbounded `Vec` in one call, with no page size, item cap, or byte cap. This is the same bug class as the Canto coinswap `GetAllBalances` finding: an attacker-controllable, unbounded-length list (access keys on an account) is fully materialized in one operation. By contrast, the semantically similar `view_state` RPC path in the same file was hardened with explicit pagination and hard page caps (`MAX_VIEW_STATE_PAGE_ITEMS`/`MAX_VIEW_STATE_PAGE_BYTES`) plus a legacy `state_size_limit` gate — but no equivalent protection exists for `view_access_keys`.

### Finding Description
`view_access_keys` in [1](#0-0)  iterates the full trie prefix for an account's access keys, parses every entry (including skipping every gas-key nonce sub-entry per gas key), and `collect()`s the whole result into memory with no limit whatsoever:

```rust
pub fn view_access_keys(...) -> Result<Vec<(PublicKeyHandle, AccessKey)>, ...> {
    let prefix = trie_key_parsers::get_raw_prefix_for_access_keys(account_id);
    let access_keys = state_update
        .iter(&prefix)?
        .map(|key| { ... })
        .filter_map_ok(|x| x)
        .collect::<Result<Vec<_>, _>>();
    access_keys
}
```

This is invoked directly for the `ViewAccessKeyList` `QueryRequest` variant [2](#0-1) , an unauthenticated, unprivileged query any RPC client can send for any account at any block. Compare this to `view_state`, which was explicitly redesigned with pagination and hard caps to avoid exactly this class of issue:

```rust
const MAX_VIEW_STATE_PAGE_ITEMS: u32 = 10_000;
const MAX_VIEW_STATE_PAGE_BYTES: u64 = 50_000;
``` [3](#0-2) 

`view_access_keys` has no analogous per-request cap, and no `state_size_limit`-style gate (that gate is only checked for the legacy, non-paginated `view_state` path) [4](#0-3) .

An account's number of access keys is bounded only by the storage-stake the account owner is willing to pay (each `AddKey` action increases `storage_usage`, requiring backing balance), not by any protocol-level cap on key count. An attacker can therefore, at a one-time storage-stake cost, create an account with an extremely large number of access keys (optionally gas keys with many nonces, multiplying the per-key work), and then have any RPC/view node pay the full iteration cost every single time anyone queries `ViewAccessKeyList` for that account — this query is free/unmetered from the caller's perspective (it's a view call, not a gas-charged transaction), so the same attacker (or anyone) can repeat it indefinitely to keep hammering RPC nodes.

This mirrors the reported coinswap bug precisely: a single upfront "seeding" action by an unprivileged actor creates an oversized, attacker-controlled collection that a later unbounded iteration routine (`k.bk.GetAllBalances` there, `view_access_keys`'s full-prefix trie iteration here) must fully process, and that routine is not gated by any size limit unlike its sibling routine which was hardened (`GetPoolBalances`'s recommended fix there mirrors the pagination fix already applied to `view_state` here, but missing for `view_access_keys`).

### Impact Explanation
Repeated `ViewAccessKeyList` queries against a poisoned account force RPC/view nodes to perform large, unbounded trie iterations and allocations on every request. Because the query itself is not gas-metered, the attacker's ongoing cost to trigger the DoS is effectively free after the initial account setup, while the node-side cost per request scales with however many access keys the attacker chose to create. This can degrade or exhaust RPC/view-node CPU and memory resources, denying service to legitimate users of that RPC endpoint — an unbounded/free-execution resource exhaustion vector, consistent with the accepted severity class in the original report (Medium).

### Likelihood Explanation
The precondition (creating an account with a very large number of access keys) requires only ordinary, unprivileged `AddKey` transactions and payment for storage stake — no special privilege or validator/node-level access is needed. Once created, the exploitation step (issuing `ViewAccessKeyList` queries) is a normal, unauthenticated RPC call available to anyone, and can be repeated without limit at negligible cost. This makes the finding realistically reachable via the standard transaction + RPC query path.

### Recommendation
Add pagination and hard per-request caps to `view_access_keys` (and the underlying `ViewAccessKeyList`/`ViewGasKeyNonces` query paths), analogous to what was already implemented for `view_state`:
- Add `after_key`/`limit` parameters (or an internal hard cap) to `view_access_keys`, bounding both the number of items processed per call and the total bytes returned.
- Consider capping the number of nonce entries skipped per gas key per page as well, since gas keys multiply the per-key iteration cost.
- Alternatively/additionally, introduce a protocol-level cap on the number of access keys (and/or total access-key storage) an account may hold, similar in spirit to `Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE` used to bound `action_delete_account`'s iteration cost [5](#0-4) .

### Proof of Concept
1. Attacker account signs a large number of `AddKey` transactions (or a small number of transactions each containing many `AddKeyAction`s) against its own account, funding enough balance to cover the resulting storage stake, to accumulate e.g. hundreds of thousands of access keys (optionally gas keys with large `num_nonces`).
2. Anyone (including the attacker) repeatedly issues the RPC query:
   ```json
   { "request_type": "view_access_key_list", "account_id": "<attacker-account>", "finality": "final" }
   ```
   which is dispatched to `TrieViewer::view_access_keys` [1](#0-0) .
3. Each such query forces the serving RPC/view node to iterate and materialize the entire access-key list for the account with no cap, unlike the pagination/caps present in the sibling `view_state` implementation [6](#0-5) , consuming disproportionate CPU/memory per request and degrading the node for other RPC consumers.

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

**File:** runtime/runtime/src/state_viewer/mod.rs (L249-264)
```rust
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
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L280-317)
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
```

**File:** core/primitives/src/views.rs (L409-411)
```rust
    ViewAccessKeyList {
        account_id: AccountId,
    },
```

**File:** runtime/runtime/src/actions.rs (L333-338)
```rust
    if account_storage_usage > Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE {
        result.result =
            Err(ActionErrorKind::DeleteAccountWithLargeState { account_id: account_id.clone() }
                .into());
        return Ok(());
    }
```
