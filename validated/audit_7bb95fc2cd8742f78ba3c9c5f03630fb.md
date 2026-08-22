### Title
Single-item bypass of the `MAX_VIEW_STATE_PAGE_BYTES` soft cap allows an attacker to inflate a single `ViewState` page response up to `max_length_storage_value` (4 MiB) per item - ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_state` checks `hit_bytes`/`hit_items` *before* appending an item, not after, so the byte cap `MAX_VIEW_STATE_PAGE_BYTES = 50_000` can be exceeded by exactly one oversized value per page. Because the runtime enforces `max_length_storage_value` (commonly 4 MiB, see `LimitConfig::max_length_storage_value`) on `storage_write`, an attacker-controlled account can write one ~4 MiB value and force a single `ViewState` RPC page response to be ~4 MiB instead of the intended ~50 KiB.

### Finding Description
In `TrieViewer::view_state` (`runtime/runtime/src/state_viewer/mod.rs:280-317`), the per-page loop only tests `hit_bytes`/`hit_items` at the *start* of each iteration, before the current item's key/value is appended to `values`/`used_bytes`: [1](#0-0) 

Because the check happens strictly before append, once `used_bytes` is below the 50,000-byte cap, the loop will still append the *next* item in full regardless of its size, and only stop on the iteration *after* that. `storage_write` in the VM host logic enforces `max_length_storage_value` (`runtime/near-vm-runner/src/logic/logic.rs:4169-4175`) — a per-protocol-config parameter that in released configs is `4_194_304` bytes (4 MiB), not bytes on the order of 50,000: [2](#0-1) 

Exploit flow:
1. Attacker (any unprivileged account) deploys a contract and calls `storage_write` with a value close to `max_length_storage_value` (e.g., ~4 MiB), which is fully permitted since it's under the configured limit.
2. Attacker (or anyone) sends a `ViewState` RPC query with `limit=1` (or no limit) against that account.
3. `view_state`'s loop begins with `used_bytes == 0`, so `hit_bytes` is `false`; it appends the ~4 MiB item, pushing `used_bytes` to ~4 MiB.
4. On the next loop iteration `hit_bytes` becomes true and the loop breaks — but the damage (returning the ~4 MiB item in the response) is already done.

The described mitigation ("soft cap, may run one item over") assumes items are bounded to something near the 50 KB page target, but the actual bound is `max_length_storage_value`, which is roughly 80x larger. This is a real gap between the intended per-page byte budget and the actual enforced per-value size limit.

### Impact Explanation
This lets an unprivileged account cause any `ViewState` RPC call against their own account to return a response up to ~4 MiB (`max_length_storage_value`) instead of the intended ~50 KB budget, per page/request. This maps to a node resource-exhaustion / DoS-adjacent bug category (bounded resource use / liveness) rather than a fund-loss or consensus-divergence bug, since `view_state` runs against local RPC-node state and does not affect consensus. The severity is limited: an RPC node processing many concurrent `ViewState` requests against such an account could see amplified memory/bandwidth usage per request (~4MB vs ~50KB, ~80x), but each request is still bounded by the hard `max_length_storage_value` limit and gas/RPC rate limiting outside this function, so it is not "arbitrarily large" as the question posits — it's bounded by an existing protocol parameter, just a much larger bound than the page target implies.

### Likelihood Explanation
Feasible and repeatable with only standard, unprivileged capabilities (deploy contract + one `storage_write` call + gas to pay for it), and no protocol-version gating stands between here and the exploit. However, it requires the attacker to pay gas/storage-usage cost for writing and permanently storing a large value (~4 MiB) under their own account, providing a natural (but not necessarily sufficient) cost deterrent. The impact per RPC call is bounded by the configured `max_length_storage_value`, not unbounded, since `storage_write` rejects values above that limit.

### Recommendation
Change the loop to check the byte/item cap only if `values` is non-empty (i.e., always return at least one item, but never let a page exceed the byte budget once at least one item has been included), OR check the cap after tentatively adding the candidate item's size, capping the value length copied into a page in a hard sense — e.g.:
```rust
if !values.is_empty() && (hit_items || hit_bytes) { break; }
```
combined with tracking `used_bytes` including the candidate before deciding to include it, so the very first (and only) item on a page cannot silently balloon page size beyond the cap when there's already accumulated content. Additionally, consider clamping/truncating oversized single-value responses in `view_state` at the RPC layer, or documenting/enforcing that `MAX_VIEW_STATE_PAGE_BYTES` bound only limits *total accumulated* bytes across multiple items, not a hard bound on any single response, and separately guard against single large items by capping `used_bytes` check to occur strictly after append but before allowing further growth (which is already the current behavior) — i.e., the real fix should ensure that once one large item is included, no further items are added (already true), but that the *first* such item is explicitly acknowledged as being bounded only by `max_length_storage_value`, and RPC-level response size limits should be added independently of this per-item pagination logic.

### Proof of Concept
Unit/integration test plan in `runtime/runtime/src/state_viewer/mod.rs` test module (or equivalent RPC test):
1. Set up a `TrieUpdate` with an account that has one contract-data key/value pair where `value.len()` ≈ `max_length_storage_value` (e.g., 4 MiB), written via a `storage_write`-equivalent trie update path.
2. Call `TrieViewer::view_state` with `limit = Some(1)` and no `after_key`.
3. Assert that `ViewStateResult.values` contains exactly one item, and that its serialized/total byte size is on the order of the written value size (~4 MiB), i.e., far exceeding `MAX_VIEW_STATE_PAGE_BYTES = 50_000`.
4. Repeat with several values of increasing size approaching `max_length_storage_value` and assert response size scales linearly with input value size (not capped near 50 KB), confirming that the byte cap is only enforced *between* items and not on the size of any single item.

### Citations

**File:** runtime/runtime/src/state_viewer/mod.rs (L302-317)
```rust
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

**File:** runtime/near-vm-runner/src/logic/logic.rs (L4168-4175)
```rust
        let value = get_memory_or_register!(self, value_ptr, value_len)?;
        if value.len() as u64 > self.config.limit_config.max_length_storage_value {
            return Err(HostError::ValueLengthExceeded {
                length: value.len() as u64,
                limit: self.config.limit_config.max_length_storage_value,
            }
            .into());
        }
```
