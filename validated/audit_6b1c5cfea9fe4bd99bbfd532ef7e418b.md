### Title
`state_size_limit` gate in `TrieViewer::view_state` bypassed via pagination, allowing unbounded full-account state iteration - ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_state` only enforces the operator-configured `state_size_limit` when the query is unpaginated (`limit.is_none() && after_key.is_none()`). An unprivileged RPC caller can trivially bypass this cap by always supplying `limit=Some(_)` (or any `after_key`), and then repeatedly paginate using the returned `last_key` to walk the entire trie subtree of any account, including ones whose `storage_usage` exceeds `state_size_limit`.

### Finding Description
`view_state` computes `paginated = limit.is_some() || after_key.is_some()` and only runs the size check inside `if !paginated { ... }`: [1](#0-0) 

The comment at line 249 ("Legacy per-account gate — paginated callers opt out of it") makes explicit that pagination is an intentional opt-out of the size limit, not an oversight bounded by another equivalent check. The per-page caps (`MAX_VIEW_STATE_PAGE_ITEMS` = 10,000 items, `MAX_VIEW_STATE_PAGE_BYTES` = 50,000 bytes) at lines 282-317 only bound the cost of a *single* page/call; they do not bound the number of pages an attacker can request, nor the aggregate account size that can be walked across many calls: [2](#0-1) 

An unprivileged RPC caller reaches this function through the public `view_state` / `EXPERIMENTAL_view_state` (or `query`-type) JSON-RPC endpoints, e.g. `chain/jsonrpc/src/api/view_state.rs` and `chain/jsonrpc/src/api/query.rs`, which forward user-supplied `prefix`, `include_proof`, and implicitly the `limit`/`after_key` pagination fields into `TrieViewer::view_state`. No authorization is required to query any account's state via these views, so any account (including one the caller does not own) with `storage_usage > state_size_limit` can have its full state read.

Exploit flow:
1. Attacker picks any account whose `storage_usage` exceeds the operator's configured `state_size_limit` (this is the exact scenario the limit was meant to reject — see the `AccountStateTooLarge` error at line 258-262).
2. Attacker calls `view_state(account, prefix=[], after_key=None, limit=Some(1))`. Because `paginated == true`, the `state_size_limit` branch at line 250 is skipped entirely, and the call succeeds, returning one item and a `last_key`.
3. Attacker repeats `view_state(account, prefix=[], after_key=Some(last_key), limit=Some(N))` for successive pages (up to `MAX_VIEW_STATE_PAGE_ITEMS`/`MAX_VIEW_STATE_PAGE_BYTES` each) until the whole account's key range is enumerated.
4. The unpaginated call to the same account would have been rejected with `AccountStateTooLarge`, but the paginated sequence achieves the identical outcome (full account state read) without ever triggering that check.

This defeats the purpose of the operator-configured `state_size_limit`, which exists specifically to bound the CPU/disk-IO cost of viewing large account state trees.

### Impact Explanation
This maps to the "node panic or unbounded resource use" impact class: an unprivileged RPC caller can force full trie iteration over an arbitrarily large account's storage on any RPC node that has configured `state_size_limit` specifically to prevent this, causing CPU and disk-IO exhaustion. Because the check is skipped for every paginated call regardless of the account queried (attacker does not need to control the account), this is a generic RPC-node resource-exhaustion vector reachable by any public API user, not just node operators.

### Likelihood Explanation
Highly likely and trivially repeatable: no special privileges, funds, or preconditions are required beyond the existence of one account (attacker's own or any other) with `storage_usage` above `state_size_limit` — a state that operators expect to be protected. The bypass requires only setting `limit=Some(1)` (or any value) instead of omitting it, which is a single-field change in a public JSON-RPC call, and the attack can be repeated indefinitely and scripted trivially to enumerate an entire account or hammer the node with many such paginated requests.

### Recommendation
Apply the `state_size_limit` check unconditionally (independent of `paginated`), or, if pagination must remain available for legitimately large accounts, replace the per-account gate with a cumulative/session-based or rate-limited cost accounting mechanism (e.g., track total bytes/items served per account per time window) so that paginated access cannot be used to circumvent the intended cap. At minimum, remove the `if !paginated` guard so oversized accounts are rejected regardless of pagination parameters, and provide a separate explicit allowance (e.g., a distinct, still-bounded "streaming" limit) if partial paginated access to large accounts is a desired feature.

### Proof of Concept
Integration test (in `runtime/runtime/src/state_viewer` tests or a JSON-RPC integration test):
1. Configure `TrieViewer::new(config_store, Some(small_limit), None)` with a small `state_size_limit`.
2. Create an account and populate its state (e.g., via contract storage writes) so its `storage_usage` exceeds `small_limit`.
3. Call `view_state(state_update, &account_id, &[], None, None, false)` — assert it returns `Err(ViewStateError::AccountStateTooLarge { .. })`.
4. Call `view_state(state_update, &account_id, &[], None, Some(NonZeroU32::new(1).unwrap()), false)` — assert it returns `Ok(..)` with a `last_key`.
5. Loop calling `view_state` with `after_key = Some(last_key)` until `last_key` is `None`, accumulating all returned `values`.
6. Assert the accumulated values reconstruct the full state of the account (equal to what an unpaginated call without the limit would have returned), proving the `state_size_limit` was fully bypassed via pagination.

### Citations

**File:** runtime/runtime/src/state_viewer/mod.rs (L233-264)
```rust
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
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L280-319)
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
```
